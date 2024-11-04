import sqlite3
import logging
import time
from asyncio import timeout
from datetime import datetime, timedelta
from fileinput import filename

from PIL.ImtImagePlugin import field
from requests.utils import select_proxy

logging.basicConfig(filename='uptime_slo.log', level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')


def process_sample_data():
    """Processes primary violations and logs Extended and Additional Violations."""

    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()
        # Perform hourly extended violation scan
        hourly_extended_violation_scan(c)
        # Perform daily additional violation scan
        daily_additional_violation_scan(c)
        conn.commit()
    time.sleep(5)
def convert_seconds(seconds):
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60

    time_parts = []
    if days > 0:
        time_parts.append(f"{days} days")
    if hours > 0:
        time_parts.append(f"{hours} hours")
    if minutes > 0:
        time_parts.append(f"{minutes} minutes")
    if seconds > 0:
        time_parts.append(f"{seconds} seconds")

    return ", ".join(time_parts)

def get_domain_ip(component_id,protocol):

    with sqlite3.connect('monitoring.db',timeout=5) as conn:
        c=conn.cursor()
        if protocol == "ICMP":

            c.execute("SELECT address FROM ICMP WHERE id = ?",(component_id,))
            address = c.fetchall()

            return address
        else:

            c.execute("SELECT url FROM HTTP WHERE id = ?",(component_id,))
            address = c.fetchall()

            return address


def daily_additional_violation_scan(cursor):
    """Hourly scan for Extended Violations if total downtime within the last hour is more than 1 minute."""


    one_hour_ago = datetime.now() - timedelta(hours=24)
    one_hour_ago = one_hour_ago.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("select * from Uptime_Violations")
    # Retrieve all Primary Violations within the last hour, grouped by component and protocol
    cursor.execute("""
        SELECT component_id, protocol, start_time
        FROM Uptime_Violations
        WHERE violation_type = 'Primary Violation' AND start_time >= ?
        ORDER BY component_id, protocol, start_time
    """, (one_hour_ago,))

    results = cursor.fetchall()

    # Dictionary to keep track of total downtime for each component and protocol
    downtime_accumulator = {}

    # Calculate total downtime per component and protocol
    while True:
        for i in range(1, len(results)):
            component_id, protocol, start_time = results[i]
            prev_component_id, prev_protocol, prev_start_time = results[i - 1]

            if component_id == prev_component_id and protocol == prev_protocol:
                # Calculate the downtime interval between consecutive Primary Violations
                interval = (datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S") -
                            datetime.strptime(prev_start_time, "%Y-%m-%d %H:%M:%S")).total_seconds()

                # Accumulate downtime for each component and protocol
                key = (component_id, protocol)
                if key not in downtime_accumulator:
                    downtime_accumulator[key] = 0
                downtime_accumulator[key] += interval
        #print(downtime_accumulator)

        # Log Extended Violations for components with total downtime > 60 seconds
        for (component_id, protocol), total_downtime in downtime_accumulator.items():

            address=get_domain_ip(component_id,protocol)



            if total_downtime > 300:
                TIME=convert_seconds(total_downtime)
                logging.warning(
                    f"Additional violation detected: Component ID {address}, Protocol {protocol}. "
                    f"Total downtime in the last 24 hours is {TIME}."
                )
                # Log Extended Violation if not already logged in the last hour
                cursor.execute("""
                    INSERT INTO Uptime_Violations (component_id, violation_type, protocol, start_time)
                    SELECT ?, 'Extended Violation', ?, ?
                    WHERE NOT EXISTS (
                        SELECT 1 FROM Uptime_Violations
                        WHERE component_id = ? AND protocol = ? AND violation_type = 'Extended Violation'
                              AND start_time >= ?
                    )
                """, (component_id, protocol, datetime.now(), component_id, protocol, one_hour_ago))
            print(downtime_accumulator)
        time.sleep(60*12*60)
def hourly_extended_violation_scan(cursor):
    """Daily scan for Additional Violations - more than 3 downtimes within 1 hours."""
    twenty_four_hours_ago = datetime.now() - timedelta(hours=1)
    twenty_four_hours_ago = twenty_four_hours_ago.timestamp()
    cursor.execute("""
        SELECT component_id, protocol, COUNT(*) AS violation_count
        FROM Uptime_Violations
        WHERE violation_type = 'Primary Violation' AND start_time >= ?
        GROUP BY component_id, protocol
    """, (twenty_four_hours_ago,))

    results = cursor.fetchall()
    while True:
        for component_id, protocol, violation_count in results:
            address=get_domain_ip(component_id,protocol)


            if violation_count > 3:
                logging.warning(
                    f"Extended violation detected at address {address} using protocol {protocol}. "
                    f"A total of {violation_count} primary violations occurred in the last hour."
                )
                # Log Additional Violation if not already logged in the last 24 hours
                cursor.execute("""
                    INSERT INTO Uptime_Violations (component_id, violation_type, protocol, start_time)
                    SELECT ?, 'Additional Violation', ?, ?
                    WHERE NOT EXISTS (
                        SELECT 1 FROM Uptime_Violations
                        WHERE component_id = ? AND protocol = ? AND violation_type = 'Additional Violation'
                              AND start_time >= ?
                    )
                """, (component_id, protocol, datetime.now(), component_id, protocol, twenty_four_hours_ago))
        time.sleep(60*60)

# Run the script
if __name__ == "__main__":

    while True:
        process_sample_data()


    time.sleep(5)
