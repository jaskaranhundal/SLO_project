import sqlite3
from time import process_time_ns

import requests
from numpy.matlib import empty
from ping3 import ping
from datetime import datetime
import time
import json
import subprocess
import logging

# Configure logging
logging.basicConfig(filename='uptime_slo.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info(f'Script start @ {datetime.now()}')
# Initialize the database and create necessary tables
def init_db():
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ICMP (
                    id INTEGER PRIMARY KEY,
                    address TEXT UNIQUE,
                    active INTEGER
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS HTTP (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    protocol TEXT,
                    port INTEGER,
                    active INTEGER
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS ResponseTimesICMP (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER,
                    response_time REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(component_id) REFERENCES ICMP(id)
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS ResponseTimesHTTP (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER,
                    response_time REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(component_id) REFERENCES HTTP(id)
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS Uptime_Violations (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER,
                    violation_type TEXT,
                    protocol TEXT,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    FOREIGN KEY(component_id) REFERENCES ICMP(id) 
                    ON DELETE CASCADE,
                    FOREIGN KEY(component_id) REFERENCES HTTP(id) 
                    ON DELETE CASCADE
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS SLOViolations (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER,
                    protocol TEXT,
                    violation_count INTEGER DEFAULT 0,
                    last_violation_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(component_id) REFERENCES ICMP(id) 
                    ON DELETE CASCADE,
                    FOREIGN KEY(component_id) REFERENCES HTTP(id) 
                    ON DELETE CASCADE
                )''')

    conn.commit()
    conn.close()

# Log ICMP response time to the database
def log_icmp_response_time(component_id, response_time):
    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO ResponseTimesICMP (component_id, response_time) VALUES (?, ?)",
                  (component_id, response_time))

# Log HTTP response time to the database
def log_http_response_time(component_id, response_time):
    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO ResponseTimesHTTP (component_id, response_time) VALUES (?, ?)",
                  (component_id, response_time))

# Log violation to the database
def log_violation(component_id,protocol, violation_type,stderr):
    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()

        c.execute("select violations_status from UptimeViolationStatus where component_id = ? AND protocol =? ", (component_id,protocol))

        status=c.fetchone()[0]


        c.execute("select * from Uptime_Violations where component_id = ? and protocol = ? and end_time IS NULL",(component_id,protocol,))
        end_time=c.fetchall()
        if protocol == "ICMP":
            address = c.execute("SELECT address from  ICMP where id = ?", (component_id,)).fetchone()[0]

        else:
            address = c.execute("SELECT url from  HTTP where id = ?", (component_id,)).fetchone()[0]
        #print(status[0], end_time)
        if end_time != []:
            if status == 0:

                c.execute("update Uptime_Violations set end_time = ? where component_id = ? and protocol = ? and start_time = ? ",
                          (datetime.now(),component_id,protocol,end_time[0][4]))
                logging.info(f"RESOLVED: Issue has been resolved for monitoring {address}, porotocol {protocol}.")
        elif status == 1:

            c.execute("INSERT INTO Uptime_Violations (component_id, violation_type,protocol) VALUES (?, ?,?)",
                  (component_id, violation_type,protocol))

            logging.error(f"Error monitoring {protocol} component ID {component_id}: {stderr.decode().strip()}")

        conn.commit()




# Calculate SLO and log if necessary
def calculate_slo(component_id, protocol):
    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()
        # Calculate uptime percentage for the component
        if protocol == "ICMP":
            c.execute(
                "SELECT COUNT(*) FROM ResponseTimesICMP WHERE component_id = ?",
                (component_id,))
            total_req= c.fetchone()[0]
            failed_req = total_req - c.execute(
                "SELECT COUNT(*) FROM ResponseTimesICMP WHERE component_id = ? AND response_time IS NULL",
                (component_id,)).fetchone()[0]
        else:
            c.execute(
                "SELECT COUNT(*) FROM ResponseTimesHTTP WHERE component_id = ?",
                (component_id,))
            total_req= c.fetchone()[0]
            failed_req = total_req - c.execute(
                "SELECT COUNT(*) FROM ResponseTimesHTTP WHERE component_id = ? AND response_time IS NULL",
                (component_id,)).fetchone()[0]
        uptime_percentage = (failed_req/total_req)*100
        c.execute("update UptimeViolationStatus set uptime_percent = ? where component_id =? and protocol = ? ", (uptime_percentage,component_id,protocol,))

# Check uptime for all components using subprocesses
def run_monitoring():
    """Run monitoring checks using subprocesses."""
    with sqlite3.connect('monitoring.db', timeout=5) as conn:
        c = conn.cursor()
        # Gather ICMP components
        c.execute("SELECT id, address FROM ICMP WHERE active = 1")
        icmp_components = c.fetchall()
        # Gather HTTP components
        c.execute("SELECT id, url, protocol FROM HTTP WHERE active = 1")
        http_components = c.fetchall()
    processes = []
    # Create subprocesses for ICMP checks
    for component_id, ip in icmp_components:
        process = subprocess.Popen(
            ['python', '-c',
             f"import json; from ping3 import ping; ip = '{ip}'; response_time = ping(ip, timeout=1); "
             f"print(json.dumps({{'component_id': {component_id}, 'protocol': 'ICMP', 'response_time': response_time * 1000 if response_time is not None else None}}))"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        processes.append((process, component_id, 'ICMP'))
    # Create subprocesses for HTTP checks
    for component_id, url , protocol in http_components:
        process = subprocess.Popen(
            ['python', '-c',
             f"import json; import requests; url = '{url}'; response = requests.get(url, timeout=5); "
             f"response_time = response.elapsed.total_seconds() * 1000 if response.status_code == 200 else None; "
             f"print(json.dumps({{'component_id': {component_id}, 'protocol': url.split('://')[0], 'response_time': response_time}}))"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        processes.append((process, component_id, protocol))
    # Collect results
    for process, component_id, protocol in processes:
        stdout, stderr = process.communicate()
        if stderr:
            log_violation(component_id,protocol, "Primary Violation",stderr)
            c.execute("UPDATE UptimeViolationStatus SET  violations_status = 1 WHERE protocol = ? AND component_id = ?",(protocol,component_id,))
            conn.commit()
            if protocol == 'ICMP':
                log_icmp_response_time(component_id, None)  # Set response time to null
            else:
                log_http_response_time(component_id, None)  # Set response time to null
            # Log or update SLO violation
            calculate_slo(component_id, protocol)
        else:
            c.execute("UPDATE UptimeViolationStatus SET  violations_status = 0 WHERE protocol = ? AND component_id = ?",
                      (protocol, component_id,))
            conn.commit()
            log_violation(component_id, protocol, "Primary Violation",None)
            result = json.loads(stdout)
            response_time = result['response_time']
            if protocol == 'ICMP':
                log_icmp_response_time(result['component_id'], response_time)
            else:
                log_http_response_time(result['component_id'], response_time)
            if response_time is None:
                log_violation(result['component_id'], protocol, "Primary Violation",None)
            calculate_slo(result['component_id'], protocol)

# Run the script every specified interval
if __name__ == '__main__':
    init_db()  # Initialize the database and create tables
    while True:
        run_monitoring()

        time.sleep(1)  # Adjust the sleep duration as necessary
