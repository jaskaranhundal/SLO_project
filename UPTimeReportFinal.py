import os
import pandas as pd
import matplotlib.pyplot as plt
import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from uptime_report import total_pings


# Cleanup function to remove old images and PDF files
def cleanup_old_files(file_paths):
    for file_path in file_paths:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                #print(f"Deleted old file: {file_path}")
            else:
                print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

# Function to get and validate a timestamp input from the user
def get_timestamp_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            timestamp = datetime.strptime(user_input, '%Y-%m-%d %H:%M:%S')
            return timestamp
        except ValueError:
            print("Invalid format. Please enter the timestamp in 'YYYY-MM-DD HH:MM:SS' format.")

# Function to plot HTTP response times and save the figure
def plot_http_response_times(start_time, end_time, file_name):
    database_path = 'monitoring.db'  # Ensure this matches the actual path of your database
    conn = sqlite3.connect(database_path)

    query = f"""
        SELECT HTTP.id AS Host_ID, HTTP.url AS Host_URL, ResponseTimesHTTP.response_time, ResponseTimesHTTP.timestamp
        FROM HTTP
        JOIN ResponseTimesHTTP ON HTTP.id = ResponseTimesHTTP.component_id
        WHERE ResponseTimesHTTP.timestamp BETWEEN '{start_time}' AND '{end_time}'
    """

    http_df = pd.read_sql_query(query, conn)
    conn.close()

    if http_df.empty:
        print("No HTTP data found within the specified time range.")
        return None

    http_df['timestamp'] = pd.to_datetime(http_df['timestamp'])
    filtered_http_df = http_df[http_df['response_time'] > 0.0]

    plt.figure(figsize=(25, 15))
    for host_id, group in filtered_http_df.groupby('Host_ID'):
        group = group.sort_values('timestamp')
        num_data_points = len(group)
        window_size = max(2, num_data_points // 2)
        group['smoothed_response_time'] = group['response_time'].rolling(window=5, min_periods=1).mean()
        plt.plot(group['timestamp'], group['smoothed_response_time'], marker='',
                 label=f"{group['Host_URL'].iloc[0]} (ID: {host_id})", linestyle='-', linewidth=1)

        # Set font sizes for the graph
    plt.xlabel('Timestamp', fontsize=14)
    plt.ylabel('Smoothed Response Time (ms)', fontsize=14)
    plt.title('HTTP Response Times for All Hosts Over Specified Period', fontsize=16)
    plt.legend(fontsize=12)
    plt.grid(True)
    plt.xticks(rotation=45, fontsize=12)  # Rotate x labels for better readability with larger font
    plt.yticks(fontsize=12)  # Increase y ticks font size
    plt.tight_layout()
    plt.savefig(file_name)
    plt.close()
# Function to plot ICMP response times and save the figure
def plot_icmp_response_times(start_time, end_time, file_name):
    database_path = 'monitoring.db'  # Ensure this matches the actual path of your database
    conn = sqlite3.connect(database_path)

    query = f"""
        SELECT ICMP.id AS Host_ID, ICMP.address AS Host_Address, ResponseTimesICMP.response_time, ResponseTimesICMP.timestamp
        FROM ICMP
        JOIN ResponseTimesICMP ON ICMP.id = ResponseTimesICMP.component_id
        WHERE ResponseTimesICMP.timestamp BETWEEN '{start_time}' AND '{end_time}'
    """

    icmp_df = pd.read_sql_query(query, conn)
    conn.close()

    if icmp_df.empty:
        print("No ICMP data found within the specified time range.")
        return None

    icmp_df['timestamp'] = pd.to_datetime(icmp_df['timestamp'])
    filtered_icmp_df = icmp_df[icmp_df['response_time'] > 0.0]

    plt.figure(figsize=(15, 8))
    for host_id, group in filtered_icmp_df.groupby('Host_ID'):
        group = group.sort_values('timestamp')
        num_data_points = len(group)
        window_size = max(2, num_data_points // 2)
        group['smoothed_response_time'] = group['response_time'].rolling(window=5, min_periods=1).mean()
        plt.plot(group['timestamp'], group['smoothed_response_time'], marker='',
                 label=f"{group['Host_Address'].iloc[0]} (ID: {host_id})", linestyle='-', linewidth=1)

    plt.xlabel('Timestamp',fontsize=14)
    plt.ylabel('Smoothed Response Time (ms)',fontsize=14)
    plt.title('Ping Response Times for All Hosts Over Specified Period',fontsize=14)
    # Set font sizes for the graph
    plt.legend(fontsize=12)
    plt.grid(True)
    plt.xticks(rotation=45, fontsize=12)  # Rotate x labels for better readability with larger font
    plt.yticks(fontsize=12)  # Increase y ticks font size
    plt.tight_layout()
    plt.savefig(file_name)
    plt.close()


# Function to create a PDF report with text tables
def create_pdf_report(start_time, end_time, http_summary, icmp_summary):
    pdf_file_name = "Monitoring_Report.pdf"
    doc = SimpleDocTemplate(pdf_file_name, pagesize=landscape(A4), rightMargin=20, leftMargin=20,
                            topMargin=20, bottomMargin=20)

    # Get sample styles
    styles = getSampleStyleSheet()

    # Prepare the elements for the PDF
    elements = []

    # Adding Title
    elements.append(Paragraph("SLO Uptime Report", styles['Title']))
    elements.append(Spacer(1, 12))  # Add space after the title

    # Adding Timeframe
    timeframe = f"From: {start_time} To: {end_time}"
    elements.append(Paragraph(timeframe, styles['Normal']))
    elements.append(Spacer(1, 12))  # Add space after timeframe

    # HTTP Summary Table
    elements.append(Paragraph("HTTP Summary Table", styles['Heading2']))
    elements.append(Spacer(1, 12))  # Add space before the table

    # Define table width to fit within margins
    max_width = doc.pagesize[0] - doc.leftMargin - doc.rightMargin
    http_data = [http_summary.columns.tolist()] + http_summary.values.tolist()
    http_table = Table(http_data, colWidths=[max_width / len(http_summary.columns)] * len(http_summary.columns))

    http_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements.append(http_table)

    # Adding HTTP Graph on the same page
    elements.append(Spacer(1, 12))  # Add some space
    elements.append(Image("http_response_times.png", width=9 * inch, height=5 * inch))

    # ICMP Summary Table
    elements.append(PageBreak())  # New page for ICMP
    elements.append(Paragraph("ICMP Summary Table", styles['Heading2']))
    elements.append(Spacer(1, 12))  # Add space before the table

    icmp_data = [icmp_summary.columns.tolist()] + icmp_summary.values.tolist()
    icmp_table = Table(icmp_data, colWidths=[max_width / len(icmp_summary.columns)] * len(icmp_summary.columns))

    icmp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements.append(icmp_table)

    # Adding ICMP Graph
    elements.append(Spacer(1, 12))  # Add some space
    elements.append(Image("icmp_response_times.png", width=9 * inch, height=5 * inch))

    # Build the PDF
    doc.build(elements)
    files_to_cleanup = ["http_response_times.png", "icmp_response_times.png"]
    cleanup_old_files(files_to_cleanup)
    print(f"PDF report generated: {pdf_file_name}")

# Main script execution
if __name__ == "__main__":
    # Cleanup old files before starting
    files_to_cleanup = ["http_response_times.png", "icmp_response_times.png", "Monitoring_Report.pdf"]
    cleanup_old_files(files_to_cleanup)

    # Define your time range here
    start_time = datetime.strptime('2024-11-04 13:30:00', '%Y-%m-%d %H:%M:%S')
    end_time = datetime.strptime('2024-11-04 15:00:00', '%Y-%m-%d %H:%M:%S')

    start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
    end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

    # Plotting and creating tables
    plot_http_response_times(start_time_str, end_time_str, "http_response_times.png")
    plot_icmp_response_times(start_time_str, end_time_str, "icmp_response_times.png")

    # Create HTTP Summary Table
    database_path = 'monitoring.db'
    conn = sqlite3.connect(database_path)
    http_query = f"""
        SELECT HTTP.id AS Host_ID, HTTP.url AS Host_URL, ResponseTimesHTTP.response_time, ResponseTimesHTTP.timestamp
        FROM HTTP
        JOIN ResponseTimesHTTP ON HTTP.id = ResponseTimesHTTP.component_id
        WHERE ResponseTimesHTTP.timestamp BETWEEN '{start_time_str}' AND '{end_time_str}'
    """
    http_df = pd.read_sql_query(http_query, conn)
    conn.close()

    http_summary_data = []
    if not http_df.empty:
        http_df['timestamp'] = pd.to_datetime(http_df['timestamp'])
        filtered_http_df = http_df[http_df['response_time'] > 0.0]

        for host_id, group in filtered_http_df.groupby('Host_ID'):
            host_url = group['Host_URL'].iloc[0]
            min_response = group['response_time'][group['response_time'] > 0].min() if any(group['response_time'] > 0) else float('nan')
            max_response = group['response_time'].max()
            avg_response = group['response_time'].mean()
            total_requests = group.shape[0]
            positive_responses = filtered_http_df[filtered_http_df['Host_ID'] == host_id].shape[0]
            uptime_percentage = (positive_responses / total_requests * 100) if total_requests > 0 else 0

            http_summary_data.append({
                'Host ID': host_id,
                'Host Address': host_url,
                'Min Response Time': f"{min_response:.3f}" if min_response > 0 else "N/A",
                'Max Response Time': f"{max_response:.3f}" if max_response > 0 else "N/A",
                'Avg Response Time': f"{avg_response:.3f}" if avg_response > 0 else "N/A",
                'Total Pings Sent': total_requests,
                'Positive Responses': positive_responses,
                'Uptime Percentage': uptime_percentage
            })

        http_summary_df = pd.DataFrame(http_summary_data)

    # Create ICMP Summary Table
    conn = sqlite3.connect(database_path)
    query_icmp = f"""
        SELECT ICMP.id AS Host_ID, ICMP.address AS Host_Address, ResponseTimesICMP.response_time, ResponseTimesICMP.timestamp
        FROM ICMP
        JOIN ResponseTimesICMP ON ICMP.id = ResponseTimesICMP.component_id
        WHERE ResponseTimesICMP.timestamp BETWEEN '{start_time_str}' AND '{end_time_str}'
    """
    icmp_df = pd.read_sql_query(query_icmp, conn)
    conn.close()

    icmp_summary_data = []
    if not icmp_df.empty:
        icmp_df['timestamp'] = pd.to_datetime(icmp_df['timestamp'])
        filtered_icmp_df = icmp_df[icmp_df['response_time'] > 0.0]

        for host_id, group in icmp_df.groupby('Host_ID'):
            host_address = group['Host_Address'].iloc[0]
            min_response = group['response_time'][group['response_time'] > 0].min() if any(group['response_time'] > 0) else float('nan')
            max_response = group['response_time'].max()
            avg_response = group['response_time'].mean()
            total_responses = group.shape[0]
            positive_responses = filtered_icmp_df[filtered_icmp_df['Host_ID'] == host_id].shape[0]
            uptime_percentage = (positive_responses / total_responses * 100) if total_responses > 0 else 0

            icmp_summary_data.append({
                'Host ID': host_id,
                'Host Address': host_address,
                'Min Response Time': f"{min_response:.3f}" if min_response > 0 else "N/A",
                'Max Response Time': f"{max_response:.3f}" if max_response > 0 else "N/A",
                'Avg Response Time': f"{avg_response:.3f}" if avg_response > 0 else "N/A",
                'Total Pings Sent': total_pings,
                'Positive Responses': positive_responses,
                'Uptime Percentage': uptime_percentage
            })
        icmp_summary_df = pd.DataFrame(icmp_summary_data)

    # Create the PDF report
    create_pdf_report(start_time_str, end_time_str, http_summary_df, icmp_summary_df)
