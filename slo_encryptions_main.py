import os
import time
import datetime
import logging
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(filename='encryption_slo.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')



logging.info(f'Script start @ {datetime.datetime.now()}')
# SQLite3 connection
db_path = os.getenv("DATABASE_URL", "monitoring.db")  # Path to SQLite database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Ensure necessary tables exist
cursor.execute('''CREATE TABLE IF NOT EXISTS storage_volumes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    volume_type TEXT,
                    volume_name TEXT UNIQUE,
                    timestamp DATETIME,
                    encrypted BOOLEAN,
                    first_unencrypted_timestamp DATETIME,
                    violation TEXT
                )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS violation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    volume_name TEXT,
                    volume_type TEXT,
                    violation_type TEXT,
                    timestamp DATETIME
                )''')

conn.commit()

# Azure subscription and credentials
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
credential = DefaultAzureCredential()

# Initialize Azure clients
storage_client = StorageManagementClient(credential, subscription_id)
compute_client = ComputeManagementClient(credential, subscription_id)


def log_audit(entity_type, action, description):
    """Log actions in the audit logs."""
    cursor.execute(
        '''INSERT INTO audit_logs (entity_type, action, description, timestamp)
           VALUES (?, ?, ?, ?)''',
        (entity_type, action, description, datetime.datetime.now())
    )
    conn.commit()


def list_storage_encryption():
    """List all Azure Storage accounts and check their encryption status."""
    logging.info("Fetching storage accounts and encryption status...")
    storage_accounts = storage_client.storage_accounts.list()

    for account in storage_accounts:
        account_name = account.name
        resource_group = account.id.split("/")[4]

        # Get encryption status
        encryption_status = get_encryption_status(resource_group, account_name)
        logging.info(f"Storage Account: {account_name}, Encryption Status: {encryption_status}")

        # Process the storage account
        process_storage_account(account_name, encryption_status)


def get_encryption_status(resource_group, storage_account_name):
    """Get the encryption settings for a specific Azure Storage account."""
    encryption = storage_client.storage_accounts.get_properties(resource_group, storage_account_name).encryption

    return encryption and encryption.services and (
            encryption.services.blob.enabled or
            encryption.services.file.enabled or
            encryption.services.table.enabled or
            encryption.services.queue.enabled
    )


def process_storage_account(account_name, encrypted):
    """Process the encryption status of the storage account."""
    current_time = datetime.datetime.now()

    cursor.execute("SELECT * FROM storage_volumes WHERE volume_name = ? AND volume_type = 'Storage Account' LIMIT 1",
                   (account_name,))
    result = cursor.fetchone()

    if not encrypted:
        if result:
            if result[5]:  # first_unencrypted_timestamp
                time_diff = current_time - datetime.datetime.fromisoformat(result[5])
                if time_diff.total_seconds() >= 86400:  # 24 hours
                    logging.warning(f"Extended Violation for Storage Account: {account_name}")
                    update_volume_violation(result[0], 'Extended')
            else:
                update_volume_first_unencrypted(result[0], current_time)
        else:
            logging.warning(f"Primary Violation for Storage Account: {account_name}")
            insert_volume('Storage Account', account_name, encrypted, 'Primary', current_time)
    else:
        if result:
            logging.info(f"Encryption applied for Storage Account: {account_name}, clearing violation")
            clear_violation(result[0])

    conn.commit()


def scan_vm_disks():
    """Scan all VM disks and check their encryption status."""
    logging.info("Scanning VM disks...")
    virtual_machines = compute_client.virtual_machines.list_all()
    current_disks = []

    for vm in virtual_machines:
        resource_group = vm.id.split("/")[4]
        vm_instance = compute_client.virtual_machines.get(resource_group, vm.name, expand='instanceView')

        # Check OS disk encryption status
        os_disk_name = vm_instance.storage_profile.os_disk.name
        os_disk_encryption_enabled = check_managed_disk_encryption(vm_instance.storage_profile.os_disk.managed_disk)

        logging.info(f"VM: {vm.name}, OS Disk: {os_disk_name}, Encryption: {os_disk_encryption_enabled}")
        process_encryption('OS Disk', os_disk_name, os_disk_encryption_enabled)
        current_disks.append((os_disk_name, os_disk_encryption_enabled))

        # Check Data disks encryption status
        for data_disk in vm_instance.storage_profile.data_disks:
            data_disk_name = data_disk.name
            data_disk_encryption_enabled = check_managed_disk_encryption(data_disk.managed_disk)
            logging.info(f"VM: {vm.name}, Data Disk: {data_disk_name}, Encryption: {data_disk_encryption_enabled}")
            process_encryption('Data Disk', data_disk_name, data_disk_encryption_enabled)
            current_disks.append((data_disk_name, data_disk_encryption_enabled))

    check_removed_vm_disks(current_disks)


def check_removed_vm_disks(current_disks):
    """Check for VM disks that have been removed or changed."""
    cursor.execute("SELECT volume_name, encrypted FROM storage_volumes WHERE volume_type IN ('OS Disk', 'Data Disk')")
    existing_disks = {row[0]: row[1] for row in cursor.fetchall()}
    current_disk_dict = {disk[0]: disk[1] for disk in current_disks}
    removed_disks = existing_disks.keys() - current_disk_dict.keys()

    for removed_disk in removed_disks:
        logging.warning(f"Removed VM Disk: {removed_disk}")
        cursor.execute("DELETE FROM storage_volumes WHERE volume_name = ?", (removed_disk,))
        log_audit('VM Disk', 'DELETE', f'Deleted VM disk: {removed_disk}')

    for disk_name, encrypted in current_disk_dict.items():
        if disk_name in existing_disks and existing_disks[disk_name] != encrypted:
            logging.info(f"Updating VM Disk: {disk_name}, New Encryption Status: {encrypted}")
            cursor.execute("UPDATE storage_volumes SET encrypted = ? WHERE volume_name = ?", (encrypted, disk_name))
            log_audit('VM Disk', 'UPDATE', f'Updated VM disk: {disk_name}')

    conn.commit()


def check_managed_disk_encryption(managed_disk):
    """Check encryption status of a managed disk."""
    return managed_disk and hasattr(managed_disk, 'encryption_settings') and managed_disk.encryption_settings.enabled


def process_encryption(volume_type, volume_name, encrypted):
    """Process the encryption status and apply violation checks."""
    current_time = datetime.datetime.now()
    cursor.execute("SELECT * FROM storage_volumes WHERE volume_name = ? LIMIT 1", (volume_name,))
    result = cursor.fetchone()

    if not encrypted:
        if result:
            if result[5]:  # first_unencrypted_timestamp
                time_diff = current_time - datetime.datetime.fromisoformat(result[5])
                if time_diff.total_seconds() >= 86400:  # 24 hours
                    logging.warning(f"Extended Violation for {volume_name}")
                    update_volume_violation(result[0], 'Extended')
                else:
                    logging.info(f"Primary Violation for {volume_name}")
                    insert_violation_history(volume_name, volume_type, 'Primary')
            else:
                update_volume_first_unencrypted(result[0], current_time)
        else:
            logging.warning(f"Primary Violation for {volume_name}")
            insert_volume(volume_type, volume_name, encrypted, 'Primary', current_time)
    else:
        if result:
            logging.info(f"Encryption applied for {volume_name}, clearing violation")
            clear_violation(result[0])

    conn.commit()


def update_volume_first_unencrypted(volume_id, timestamp):
    """Update volume with the first unencrypted timestamp."""
    cursor.execute("UPDATE storage_volumes SET first_unencrypted_timestamp = ? WHERE id = ?", (timestamp, volume_id))
    conn.commit()


def update_volume_violation(volume_id, violation_type):
    """Update volume with the specified violation."""
    cursor.execute("UPDATE storage_volumes SET violation = ? WHERE id = ?", (violation_type, volume_id))
    conn.commit()
    # Log the violation history
    cursor.execute("SELECT volume_name, volume_type FROM storage_volumes WHERE id = ?", (volume_id,))
    volume_data = cursor.fetchone()
    if volume_data:
        insert_violation_history(volume_data[0], volume_data[1], violation_type)


def clear_violation(volume_id):
    """Clear any violation and reset the first unencrypted timestamp."""
    cursor.execute("UPDATE storage_volumes SET violation = NULL, first_unencrypted_timestamp = NULL WHERE id = ?",
                   (volume_id,))
    conn.commit()


def insert_volume(volume_type, volume_name, encrypted, violation, first_unencrypted_timestamp=None):
    """Insert a new volume entry into the database."""
    logging.info(f"Inserting volume: {volume_name}, Encrypted: {encrypted}, Violation: {violation}")
    cursor.execute(
        '''INSERT INTO storage_volumes (volume_type, volume_name, timestamp, encrypted, violation, first_unencrypted_timestamp)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (volume_type, volume_name, datetime.datetime.now(), encrypted, violation, first_unencrypted_timestamp)
    )
    conn.commit()


def insert_violation_history(volume_name, volume_type, violation_type):
    """Insert a new entry into the violation history table."""
    logging.info(f"Inserting violation history: {volume_name}, Violation: {violation_type}")
    cursor.execute(
        '''INSERT INTO violation_history (volume_name, volume_type, violation_type, timestamp)
           VALUES (?, ?, ?, ?)''',
        (volume_name, volume_type, violation_type, datetime.datetime.now())
    )
    conn.commit()


def generate_report():
    """Generate a report of the current encryption status and violations."""
    # Count total volumes and encrypted volumes
    cursor.execute(
        "SELECT volume_type, COUNT(*) as count, SUM(CASE WHEN encrypted THEN 1 ELSE 0 END) as encrypted_count FROM storage_volumes GROUP BY volume_type")
    df = pd.DataFrame(cursor.fetchall(), columns=['volume_type', 'count', 'encrypted_count'])

    # Plotting the data
    plt.figure(figsize=(10, 5))
    plt.bar(df['volume_type'], df['count'], color='blue', label='Total Volumes')
    plt.bar(df['volume_type'], df['encrypted_count'], color='green', label='Encrypted Volumes', alpha=0.7)
    plt.xlabel('Volume Type')
    plt.ylabel('Count')
    plt.title('Volume Encryption Status')
    plt.legend()
    plt.savefig('volume_encryption_report.png')
    plt.close()

    # Generate a summary table
    summary_table = df.to_string(index=False)
    logging.info(f"Summary Report:\n{summary_table}")

    # Generate a violation history report
    cursor.execute(
        "SELECT volume_type, violation_type, COUNT(*) as violation_count FROM violation_history GROUP BY volume_type, violation_type")
    violation_df = pd.DataFrame(cursor.fetchall(), columns=['volume_type', 'violation_type', 'violation_count'])
    violation_summary = violation_df.to_string(index=False)
    logging.info(f"Violation History Report:\n{violation_summary}")


if __name__ == "__main__":
    try:
        while True:
            # Scan storage accounts
            list_storage_encryption()

            # Scan disks used by virtual machines
            scan_vm_disks()

            # Generate and log reports
            generate_report()

            # Sleep for 10 seconds before next iteration
            time.sleep(3600)

    finally:
        conn.close()  # Close the database connection when done
