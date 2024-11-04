import pandas as pd
import matplotlib.pyplot as plt
import sqlite3
from datetime import datetime


# Function to get and validate a timestamp input from the user
def get_timestamp_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            # Convert the input to a datetime object to validate it
            timestamp = datetime.strptime(user_input, '%Y-%m-%d %H:%M:%S')
            return timestamp
        except ValueError:
            print("Invalid format. Please enter the timestamp in 'YYYY-MM-DD HH:MM:SS' format.")


# Function to plot HTTP response times
def plot_http_response_times(start_time, end_time):
    database_path = 'monitoring.db'  # Ensure this matches the actual path of your database
    conn = sqlite3.connect(database_path)

    # SQL query to join tables, filter by time range, and retrieve HTTP response times
    query = f"""
        SELECT HTTP.id AS Host_ID, HTTP.url AS Host_URL, ResponseTimesHTTP.response_time, ResponseTimesHTTP.timestamp
        FROM HTTP
        JOIN ResponseTimesHTTP ON HTTP.id = ResponseTimesHTTP.component_id
        WHERE ResponseTimesHTTP.timestamp BETWEEN '{start_time}' AND '{end_time}'
    """

    # Execute query and load data into a DataFrame
    http_df = pd.read_sql_query(query, conn)
    conn.close()

    # Check if data was returned
    if http_df.empty:
        print("No HTTP data found within the specified time range.")
        return

    # Convert timestamp column to datetime type for easier plotting and filtering
    http_df['timestamp'] = pd.to_datetime(http_df['timestamp'])

    # Filter out 0.0 and NaN values for positive responses
    filtered_http_df = http_df[http_df['response_time'] > 0.0]

    # Group data by each host to calculate metrics per host, ignoring 0.0 and NaN for min calculation
    summary_data = []
    for host_id, group in http_df.groupby('Host_ID'):
        # Calculate metrics for each host
        host_url = group['Host_URL'].iloc[0]

        # Calculate minimum response time, ignoring 0 and NaN
        min_response = group['response_time'][group['response_time'] > 0].min() if any(
            group['response_time'] > 0) else float('nan')

        max_response = group['response_time'].max()
        avg_response = group['response_time'].mean()
        total_responses = group.shape[0]  # Total responses (including 0s and NaNs)
        positive_responses = filtered_http_df[filtered_http_df['Host_ID'] == host_id].shape[
            0]  # Positive responses only

        uptime_percentage = (positive_responses / total_responses) * 100 if total_responses > 0 else 0

        # Append metrics to summary data
        summary_data.append({
            'Host ID': host_id,
            'Host URL': host_url,
            'Min Response Time': min_response,
            'Max Response Time': max_response,
            'Avg Response Time': avg_response,
            'Total Requests Sent': total_responses,
            'Positive Responses': positive_responses,
            'Uptime Percentage': uptime_percentage
        })

    # Create and display the summary table as a DataFrame
    summary_http_df = pd.DataFrame(summary_data)
    print("Summary Table for HTTP Hosts:")
    print(summary_http_df)

    # Plotting a single combined line graph of HTTP response times for all hosts
    plt.figure(figsize=(15, 8))
    for host_id, group in filtered_http_df.groupby('Host_ID'):
        # Sort the group by timestamp to ensure proper plotting
        group = group.sort_values('timestamp')

        # Determine the moving average window size dynamically
        num_data_points = len(group)
        window_size = max(2, num_data_points // 2)  # Minimum of 2 to avoid division by zero

        # Calculate moving average
        group['smoothed_response_time'] = group['response_time'].rolling(window=5, min_periods=1).mean()

        # Plot smooth line
        plt.plot(group['timestamp'], group['smoothed_response_time'], marker='',
                 label=f"{group['Host_URL'].iloc[0]} (ID: {host_id})", linestyle='-', linewidth=1)

    plt.xlabel('Timestamp')
    plt.ylabel('Smoothed Response Time (ms)')
    plt.title('HTTP Response Times for All Hosts Over Specified Period (Automatically Smoothed)')
    plt.legend()
    plt.grid(True)
    plt.xticks(rotation=45)  # Rotate x labels for better readability
    plt.tight_layout()  # Adjust layout to prevent clipping of tick-labels
    plt.show()


# Main Execution

# Use hardcoded timestamps for testing
start_time = datetime.strptime('2024-11-04 13:30:00', '%Y-%m-%d %H:%M:%S')
end_time = datetime.strptime('2024-11-04 15:00:00', '%Y-%m-%d %H:%M:%S')

# Convert timestamps to string format for SQL query
start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

# Connect to SQLite database named 'monitoring'
database_path = 'monitoring.db'  # Ensure this matches the actual path of your database
conn = sqlite3.connect(database_path)

# SQL query to join tables, filter by time range, and retrieve all hosts
icmp_query = f"""
    SELECT ICMP.id AS Host_ID, ICMP.address AS Host_Address, ResponseTimesICMP.response_time, ResponseTimesICMP.timestamp
    FROM ICMP
    JOIN ResponseTimesICMP ON ICMP.id = ResponseTimesICMP.component_id
    WHERE ResponseTimesICMP.timestamp BETWEEN '{start_time_str}' AND '{end_time_str}'
"""

# Execute query and load data into a DataFrame for ICMP
icmp_df = pd.read_sql_query(icmp_query, conn)

# Close database connection
conn.close()

# Check if data was returned
if icmp_df.empty:
    print("No ICMP data found within the specified time range.")
else:
    # Convert timestamp column to datetime type for easier plotting and filtering
    icmp_df['timestamp'] = pd.to_datetime(icmp_df['timestamp'])

    # Filter out 0.0 and NaN values for positive responses
    filtered_icmp_df = icmp_df[icmp_df['response_time'] > 0.0]

    # Group data by each host to calculate metrics per host, ignoring 0.0 and NaN for min calculation
    summary_data = []
    for host_id, group in icmp_df.groupby('Host_ID'):
        # Calculate metrics for each host
        host_address = group['Host_Address'].iloc[0]

        # Calculate minimum response time, ignoring 0 and NaN
        min_response = group['response_time'][group['response_time'] > 0].min() if any(
            group['response_time'] > 0) else float('nan')

        max_response = group['response_time'].max()
        avg_response = group['response_time'].mean()
        total_pings = group.shape[0]  # Total pings (including 0s and NaNs)
        positive_responses = filtered_icmp_df[filtered_icmp_df['Host_ID'] == host_id].shape[
            0]  # Positive responses only

        uptime_percentage = (positive_responses / total_pings) * 100 if total_pings > 0 else 0

        # Append metrics to summary data
        summary_data.append({
            'Host ID': host_id,
            'Host Address': host_address,
            'Min Response Time': min_response,
            'Max Response Time': max_response,
            'Avg Response Time': avg_response,
            'Total Pings Sent': total_pings,
            'Positive Responses': positive_responses,
            'Uptime Percentage': uptime_percentage
        })

    # Create and display the summary table as a DataFrame for ICMP
    summary_icmp_df = pd.DataFrame(summary_data)
    print("Summary Table for ICMP Hosts:")
    print(summary_icmp_df)

    # Plotting a single combined line graph of response times for all hosts
    plt.figure(figsize=(15, 8))
    for host_id, group in filtered_icmp_df.groupby('Host_ID'):
        # Sort the group by timestamp to ensure proper plotting
        group = group.sort_values('timestamp')

        # Determine the moving average window size dynamically
        num_data_points = len(group)
        window_size = max(2, num_data_points // 2)  # Minimum of 2 to avoid division by zero

        # Calculate moving average
        group['smoothed_response_time'] = group['response_time'].rolling(window=5, min_periods=1).mean()

        # Plot smooth line
        plt.plot(group['timestamp'], group['smoothed_response_time'], marker='',
                 label=f"{group['Host_Address'].iloc[0]} (ID: {host_id})", linestyle='-', linewidth=1)

    plt.xlabel('Timestamp')
    plt.ylabel('Smoothed Response Time (ms)')
    plt.title('Ping Response Times for All Hosts Over Specified Period (Automatically Smoothed)')
    plt.legend()
    plt.grid(True)
    plt.xticks(rotation=45)  # Rotate x labels for better readability
    plt.tight_layout()  # Adjust layout to prevent clipping of tick-labels
    plt.show()

# Call the function to plot HTTP response times
plot_http_response_times(start_time_str, end_time_str)
