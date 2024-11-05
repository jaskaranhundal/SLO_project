import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime

# Step 1: Connect to the database and fetch data
conn = sqlite3.connect('monitoring.db')

# Query to retrieve data
query = """
SELECT 
    ROW_NUMBER() OVER() AS sr_no, 
    volume_type AS disk_type, 
    volume_name AS disk_name, 
    CASE 
        WHEN encrypted = 1 THEN 'Yes' 
        ELSE 'No' 
    END AS encryption_status 
FROM 
    storage_volumes;
"""

# Load the data into a DataFrame
summary_df = pd.read_sql_query(query, conn)

# Close the database connection
conn.close()

# Step 2: Print the summary DataFrame (for debugging)


# Step 3: Create a bar graph for encryption vs unencrypted
encryption_counts = summary_df['encryption_status'].value_counts()

# Prepare data for bar graph
labels = ['Encrypted', 'Unencrypted']
sizes = [encryption_counts.get('Yes', 0), encryption_counts.get('No', 0)]
colors = ['lightblue', 'red']

# Plot the bar graph
plt.figure(figsize=(8, 6))
plt.bar(labels, sizes, color=colors, alpha=0.7)
plt.title('Encryption Status of Storage Volumes')
plt.xlabel('Status')
plt.ylabel('Count')
plt.ylim(0, max(sizes) + 1)
plt.yticks(range(0, max(sizes) + 2))# Add some space above the highest bar
plt.grid(axis='y')

# Save the bar graph as an image
plt.savefig("encryption_status_bar_graph.png")
plt.close()

# Step 4: Create the PDF report in landscape orientation
pdf = FPDF(orientation='L', unit='mm', format='A4')  # Set to landscape orientation
pdf.add_page()

# PDF Title
pdf.set_font("Arial", "B", 16)
pdf.cell(0, 10, "SLO Storage encryption Summary Report", ln=True, align='C')
pdf.ln(10)

# Add the summary table
pdf.set_font("Arial", "B", 12)
pdf.cell(15, 10, "Sr No", 1)
pdf.cell(30, 10, "Disk Type", 1)
pdf.cell(150, 10, "Disk Name", 1)
pdf.cell(50, 10, "Encryption Status", 1)
pdf.ln()

pdf.set_font("Arial", "", 12)
for index, row in summary_df.iterrows():
    pdf.cell(15, 10, str(row['sr_no']), 1)
    pdf.cell(30, 10, row['disk_type'], 1)
    pdf.cell(150, 10, row['disk_name'], 1)
    pdf.cell(50, 10, row['encryption_status'], 1)
    pdf.ln()

pdf.ln(10)  # Add some space before the chart

# Add the bar graph to the PDF
pdf.image("encryption_status_bar_graph.png", x=30, w=150)




pdf_file = f"SLO_Encryption_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
pdf.output(pdf_file)
os.remove('encryption_status_bar_graph.png')

print(f"Report generated and saved as {pdf_file}")
