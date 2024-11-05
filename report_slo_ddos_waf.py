import sqlite3,os
from time import process_time_ns

import pandas as pd
from fpdf import FPDF
import matplotlib.pyplot as plt
from datetime import datetime

def get_timestamp_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            timestamp = datetime.strptime(user_input, '%Y-%m-%d %H:%M:%S')
            return timestamp
        except ValueError:
            print("Invalid format. Please enter the timestamp in 'YYYY-MM-DD HH:MM:SS' format.")

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, 'SLO DDoS Report', 0, 1, 'C')

    def footer(self):
        self.set_y(-25)
        self.set_font("Arial", 'I', 8)
        self.multi_cell(0, 10,
                       "Note: For more detilas please refer to the log file 'waf_slo.log'.This log contains detailed records that may provide "
                       "insights into the absence of data or any anomalies observed during the logging period.",
                       align='L'
                       )
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

# Connect to the SQLite database
conn = sqlite3.connect('monitoring.db')  # Replace 'your_database.db' with your database path

# User inputs for timeframe
'''start_time = input("Enter start date (YYYY-MM-DD HH:MM:SS): ")
end_time = input("Enter end date (YYYY-MM-DD HH:MM:SS): ")'''

# Define your time range here
start_time = datetime.strptime('2024-11-04 13:30:00', '%Y-%m-%d %H:%M:%S')
end_time = datetime.strptime('2024-11-04 18:00:00', '%Y-%m-%d %H:%M:%S')
### Step 1: Data Processing
start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

# Query for the logs table to generate summary data
logs_query = f"""
SELECT ip_address, action, ruleSetType, ruleGroup, COUNT(*) as total_requests
FROM logs
WHERE timestamp BETWEEN '{start_time_str}' AND '{end_time_str}'
GROUP BY ip_address, ruleSetType, ruleGroup
ORDER BY total_requests DESC;
"""

# Read logs data into DataFrame
logs_df = pd.read_sql_query(logs_query, conn)

# Add serial number for the report table
logs_df.reset_index(inplace=True)
logs_df['sr_no'] = logs_df.index + 1
logs_df = logs_df[['sr_no', 'ip_address', 'total_requests', 'action', 'ruleGroup', 'ruleSetType']]


# Query for the violations table to calculate success rates
violations_query = f"""
SELECT violation_type,
       SUM(primary_status = 1) AS primary_violations,
       SUM(primary_status = 0) AS primary_success,
       SUM(extended_status = 1) AS extended_violations,
       SUM(extended_status = 0) AS extended_success
       
FROM violations

"""

# Read violations data into DataFrame
violations_df = pd.read_sql_query(violations_query, conn)
conn.close()

# Calculate success percentages for primary and extended violations
violations_df['Total_attack_manual']=  (violations_df['primary_violations'] + violations_df['primary_success'])

violations_df['primary_success_rate']  = violations_df['primary_success']  * 100 / (
    violations_df['primary_violations'] + violations_df['primary_success'])
violations_df['extended_success_rate'] = violations_df['extended_success'] * 100 / (
    violations_df['extended_violations'] + violations_df['extended_success'])

### Step 2: Generate Graphs
if not violations_df.empty and 'primary_success_rate' in violations_df.columns and 'extended_success_rate' in violations_df.columns:
    plt.figure(figsize=(10, 5))

    # Plot both success rates, ensuring alignment by using the violation_type column as x-axis labels
    plt.bar( 'Primary(within 20 sec) ',violations_df['primary_success_rate'],
            color='blue', alpha=1, width=0.4, align='center', label=f'Primary Success Rate: {round(violations_df['primary_success_rate'][0],2)}')

    plt.bar( 'Extended (With in 10 min) ',violations_df['extended_success_rate'],
            color='green', alpha=1, width=0.4, align='edge', label=f'Extended Success Rate: {round(violations_df['extended_success_rate'][0],2)}')

    plt.xlabel("Violation Type")
    plt.ylabel("Success Rate (%)")
    plt.title(f"Primary and Extended Violation Success Rates \n Total simulation attack {violations_df['Total_attack_manual'][0] }")

    plt.legend()
    plt.savefig("success_rates.png")

else:
    print("No data available to plot the success rates graph.")

### Step 3: Create PDF Report

# Create PDF
pdf =PDF(orientation='L', unit='mm', format='A4')
pdf.add_page()

# Title and Metadata
pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, f"Violation Report from {start_time} to {end_time}", ln=True, align='C')
pdf.ln(10)

# Table Header
pdf.set_font("Arial", "B", 10)
pdf.cell(11, 10, "Sr No", 1)
pdf.cell(30, 10, "IP Address", 1)
pdf.cell(30, 10, "Total Requests", 1)
pdf.cell(15, 10, "Action", 1)
pdf.cell(70, 10, "Rule Group", 1)
pdf.cell(50, 10, "Rule Set Type", 1)
pdf.ln()

# Table Rows
pdf.set_font("Arial", "", 10)
for index, row in logs_df.iterrows():
    pdf.cell(11, 10, str(row['sr_no']), 1)
    pdf.cell(30, 10, row['ip_address'], 1)
    pdf.cell(30, 10, str(row['total_requests']), 1)
    pdf.cell(15, 10, row['action'], 1)
    pdf.cell(70, 10, row['ruleGroup'], 1)
    pdf.cell(50, 10, row['ruleSetType'], 1)
    pdf.ln()

# Add graph image
pdf.ln(10)
pdf.ln(10)
pdf.ln(10)
image_path = "success_rates.png"

pdf_width = pdf.w - 20  # Width of the page with a small margin
image_width = 200  # Desired image width

# Calculate the centered x position
x_position = (pdf_width - image_width) / 2
print(pdf.w,image_width,x_position)
# Insert the image centered
pdf.image(image_path, x=x_position, w=image_width)


# Save PDF
pdf_file = f"SLO_DDoS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
pdf.output(pdf_file)

# Close the database connection
conn.close()
os.remove(image_path)
print(f"Report generated and saved as {pdf_file}")
