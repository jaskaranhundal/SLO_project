import sqlite3
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    filename='log_evaluation.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Database setup
conn = sqlite3.connect("monitoring.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    violation_type TEXT,
                    timestamp TEXT,
                    primary_status INTEGER,  -- 0 for no primary violation, 1 if primary violation detected
                    extended_status INTEGER  -- 0 for no extended violation, 1 if extended violation detected
                )''')

# New table to store success rates
cursor.execute('''CREATE TABLE IF NOT EXISTS violation_rates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    primary_success_rate REAL,
                    extended_success_rate REAL
                )''')
conn.commit()


def evaluate_logs(ip_address, start_time):
    # Parse input time and calculate end_time as start_time + 20 seconds
    start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
    end_dt = start_dt + timedelta(seconds=20)

    # Query logs for the primary time range (20 seconds after start_time)
    cursor.execute('''SELECT * FROM logs 
                      WHERE ip_address = ? AND timestamp BETWEEN ? AND ?''',
                   (ip_address, start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")))
    primary_logs = cursor.fetchall()

    # Initialize violation tracking
    violation_type = "No Violation"
    primary_status = 0  # 0 means no primary violation detected, 1 means primary violation
    extended_status = 0  # 0 means no extended violation detected, 1 means extended violation

    # Check for primary violation
    if not primary_logs:
        # No primary logs found, check extended timeframe
        new_end_time = end_dt + timedelta(minutes=10)
        cursor.execute('''SELECT * FROM logs 
                          WHERE ip_address = ? AND timestamp BETWEEN ? AND ?''',
                       (ip_address, end_dt.strftime("%Y-%m-%d %H:%M:%S"), new_end_time.strftime("%Y-%m-%d %H:%M:%S")))
        extended_logs = cursor.fetchall()

        if not extended_logs:
            # No logs in both primary and extended timeframes; mark as unsuccessful detection
            violation_type = "Unsuccessful Detection"
            primary_status = 1
            extended_status = 1

            logging.warning(f"Violation: {violation_type} for IP {ip_address}")
        else:
            # Logs found in extended timeframe only; mark as extended violation
            violation_type = "Primary Violation"
            extended_status = 0
            primary_status = 1
            logging.warning(f"Violation: {violation_type} for IP {ip_address}")
    else:
        # Logs found in primary timeframe, mark as successful detection (no violation)
        violation_type = "Detection Success"
        logging.info(f"No violations detected for IP {ip_address} in the primary timeframe.")

    # Insert result into the database
    cursor.execute('''INSERT INTO violations (ip_address, violation_type, timestamp, primary_status, extended_status)
                      VALUES (?, ?, ?, ?, ?)''',
                   (ip_address, violation_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), primary_status,
                    extended_status))
    conn.commit()

    # Calculate and store success rates
    calculate_and_store_success_rates()


def calculate_and_store_success_rates():
    # Get total records and successful records for primary and extended status
    cursor.execute("SELECT COUNT(*) FROM violations")
    total_records = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM violations WHERE primary_status = 0")
    primary_success_count = cursor.fetchone()[0]
    primary_success_rate = (primary_success_count / total_records) * 100 if total_records > 0 else 0

    cursor.execute("SELECT COUNT(*) FROM violations WHERE extended_status = 0")
    extended_success_count = cursor.fetchone()[0]
    extended_success_rate = (extended_success_count / total_records) * 100 if total_records > 0 else 0

    # Log success rate if either rate falls below 99%
    if primary_success_rate < 99 or extended_success_rate < 99:
        logging.warning(f"Success Rate Warning: Primary Success Rate = {primary_success_rate:.2f}%, "
                        f"Extended Success Rate = {extended_success_rate:.2f}%")

    # Store success rates in violation_rates table
    cursor.execute('''INSERT INTO violation_rates (timestamp, primary_success_rate, extended_success_rate)
                      VALUES (?, ?, ?)''',
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), primary_success_rate, extended_success_rate))
    conn.commit()


if __name__ == "__main__":
    ip = input("Enter IP address to evaluate: ")
    start_time = input("Enter start time (YYYY-MM-DD HH:MM:SS): ")
    evaluate_logs(ip, start_time)
