import pandas as pd
import sqlite3
import matplotlib.pyplot as plt
from datetime import datetime
from fpdf import FPDF
import os


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


# Function to create a PDF report
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, 'SLO Security Headers Report', 0, 1, 'C')

    def footer(self):
        self.set_y(-25)
        self.set_font("Arial", 'I', 8)
        self.multi_cell(0, 10,
                       "Note: For any missing header counts within the specified time frame, please refer to the log file located at 'http_header_slo.log'. "
                       "This log contains detailed records that may provide insights into the absence of data or any anomalies observed during the logging period.",
                       align='L'
                       )
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')


# Prompt the user for start and end times
'''start_time = get_timestamp_input("Enter the start time (YYYY-MM-DD HH:MM:SS): ")
end_time = get_timestamp_input("Enter the end time (YYYY-MM-DD HH:MM:SS): ")'''
# Define your time range here
start_time = datetime.strptime('2024-11-04 13:30:00', '%Y-%m-%d %H:%M:%S')
end_time = datetime.strptime('2024-11-04 18:00:00', '%Y-%m-%d %H:%M:%S')

start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

# Connect to SQLite database
database_path = 'monitoring.db'  # Change this to your database path
conn = sqlite3.connect(database_path)

# SQL query to get header counts grouped by URL within the time frame
query = f"""
    SELECT 
        url,
        COUNT(*) AS total_requests,
        SUM(hsts) AS hsts_count,
       
        SUM(x_con_typ_opt) AS x_con_typ_opt_count,
        SUM(x_xss_pro) AS x_xss_pro_count,
      
        SUM(forward_secrecy) AS forward_secrecy_count
    FROM http_header
    WHERE timestamp BETWEEN '{start_time}' AND '{end_time}'
    GROUP BY url
"""

# Execute the query and fetch the results
results = pd.read_sql_query(query, conn)
conn.close()

# Check if any results were returned
if results.empty or results['total_requests'].sum() == 0:
    print("No requests found within the specified time range.")
else:
    # Create a summary DataFrame
    summary_df = results


    # Create bar chart for HTTP headers across URLs
    headers = [
        ('hsts_count', 'HSTS'),

        ('x_con_typ_opt_count', 'X-Content-Type-Options'),
        ('x_xss_pro_count', 'X-XSS-Protection'),

        ('forward_secrecy_count', 'Forward Secrecy')
    ]

    plt.figure(figsize=(10, 6))

    # Plot bars for each header
    bar_width = 0.15
    x = range(len(summary_df))

    for i, (col_name, header_label) in enumerate(headers):
        plt.bar(
            [p + bar_width * i for p in x],
            summary_df[col_name],
            width=bar_width,
            label=header_label
        )

    plt.title('HTTP Header Responses by URL')
    plt.xlabel('URLs')
    plt.ylabel('Count of Responses')
    plt.xticks([p + bar_width * (len(headers) / 2 - 0.5) for p in x], summary_df['url'], rotation=0)
    plt.legend()
    plt.tight_layout()

    # Save the bar chart
    chart_file_name = 'http_header_chart.png'
    plt.savefig(chart_file_name)
    plt.close()  # Close the plot to free up memory

    # Create a PDF report
    pdf = PDF(orientation='L', unit='mm', format='A4')
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add the header information
    pdf.cell(0, 10, f"Report from {start_time} to {end_time}", 0, 1, 'C')
    pdf.cell(0, 10, '', 0, 1)  # Blank line

    # Add the summary table
    pdf.cell(0, 10, "Summary of Requests and Header Counts:", 0, 1)

    # Adding headers for the table
    pdf.cell(70, 10, "URL", 1)
    pdf.cell(35, 10, "Total Requests", 1)
    pdf.cell(35, 10, "HSTS Count", 1)
    #pdf.cell(30, 10, "CSP Count", 1)
    pdf.cell(45, 10, "X-Content Count", 1)
    pdf.cell(35, 10, "X-XSS Count", 1)
    #pdf.cell(30, 10, "X-Frame Count", 1)
    pdf.cell(35, 10, "FS Count", 1)
    pdf.ln()

    # Adding data rows
    for index, row in summary_df.iterrows():

        pdf.cell(70, 10, row['url'], 1)
        pdf.cell(35, 10, str(row['total_requests']), 1)
        pdf.cell(35, 10, str(row['hsts_count']), 1)
        #pdf.cell(30, 10, str(row['con_sec_pol_count']), 1)
        pdf.cell(45, 10, str(row['x_con_typ_opt_count']), 1)
        pdf.cell(35, 10, str(row['x_xss_pro_count']), 1)
        #pdf.cell(30, 10, str(row['x_frame_pro_count']), 1)
        pdf.cell(35, 10, str(row['forward_secrecy_count']), 1)
        pdf.ln()

    # Add the chart to the PDF
    pdf.image(chart_file_name, x=10, y=pdf.get_y() + 10, w=150)  # Position the image on the page

    pdf.cell(0, 10, '', 0, 1)  # Blank line

    # Add the professional note at the bottom of the report
    pdf.cell(0, 60, '', 0, 1)  # Blank line
    pdf.set_font("Arial", 'I', 8)


    # Save the PDF to a file
    pdf_file = f"SLO_Security_Headers_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(pdf_file)

    # Clean up: remove the chart image file
    os.remove(chart_file_name)

    #print(f"Report saved as {pdf_file}")
