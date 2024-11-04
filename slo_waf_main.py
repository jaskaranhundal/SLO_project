import os
import time
import sqlite3
import logging
from datetime import datetime, timedelta , timezone

from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging to file only
logging.basicConfig(
    level=logging.DEBUG,  # Set the desired logging level
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("waf_slo.log"),  # Logs only to a file
    ]
)
logging.info(f'Script start @ {datetime.now()}')
# Azure setup
credential = DefaultAzureCredential()
client = LogsQueryClient(credential)
log_query = "AzureDiagnostics | where ResourceType == 'APPLICATIONGATEWAYS' | where action_s == 'Blocked'"

# Database setup
conn = sqlite3.connect("monitoring.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip_address TEXT,
                    request_uri TEXT,
                    action TEXT,
                    message TEXT,
                    ruleSetType TEXT,
                    ruleGroup TEXT
                )''')
conn.commit()


def fetch_and_store_logs():
    try:
        logging.info("Starting log fetch and store operation.")

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        #logging.debug(f"Fetching logs from {start_time} to {end_time}.")

        query_result = client.query_workspace(
            workspace_id=os.getenv("WORKSPACE_ID"),
            query=log_query,
            timespan=(start_time, end_time)
        )

        # Process each table in the query result
        for table in query_result.tables:
            column_names = table.columns
            #logging.debug(f"Column names: {column_names}")

            # Map required fields by name
            try:
                time_index = column_names.index("TimeGenerated")
                ip_index = column_names.index("clientIp_s")
                uri_index = column_names.index("requestUri_s")
                actions_index = column_names.index("action_s")
                message_index = column_names.index("Message")
                ruleSetType_index = column_names.index("ruleSetType_s")
                ruleGroup_index = column_names.index("ruleGroup_s")
            except ValueError as e:
                logging.error(f"Column name error: {e}")
                continue

            # Process each row
            for row in table.rows:
                timestamp_raw = row[time_index]
                timestamp = timestamp_raw.strftime("%Y-%m-%d %H:%M:%S") if isinstance(timestamp_raw,
                                                                                      datetime) else timestamp_raw
                ip_address = row[ip_index]
                request_uri = row[uri_index]
                action = row[actions_index]
                message = row[message_index]
                ruleSetType = row[ruleSetType_index]
                ruleGroup = row[ruleGroup_index]

                # Log data insertion at debug level
                #logging.debug(f"Inserting log entry: IP={ip_address}, URI={request_uri}, Action={action}")

                cursor.execute('''
                    INSERT INTO logs (timestamp, ip_address, request_uri, action, message, ruleSetType, ruleGroup)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, ip_address, request_uri, action, message, ruleSetType, ruleGroup))

        conn.commit()
        logging.info("Log fetch and store operation completed successfully.")

    except ResourceNotFoundError as e:
        logging.error("ResourceNotFoundError: Check the workspace ID and the query syntax.")
        #logging.debug(f"Error details: {e}")
    except HttpResponseError as e:
        logging.error("HttpResponseError: An error occurred with the Azure API request.")
        #logging.debug(f"Error details: {e}")
    except Exception as e:
        logging.error("An unexpected error occurred.")
        #logging.debug(f"Error details: {e}", exc_info=True)


if __name__ == "__main__":
    logging.info("Starting the WAF log monitoring script.")
    while True:
        fetch_and_store_logs()
        logging.info("Sleeping for 5 minutes.")
        time.sleep(300)  # Run every 5 minutes
