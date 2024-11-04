import multiprocessing
import subprocess
import datetime

# Define the list of scripts you want to run
scripts = [
    'slo_encryptions_main.py',
    'slo_http-https-security_main.py',
    'slo_uptime_main.py',
    'slo_waf_main.py',
    'uptime_violations.py'
]

# Function to run a script
def run_script(script_name):
    subprocess.run(['python3', script_name])  # Change 'python3' to 'python' if needed

if __name__ == '__main__':
    # Create a list to hold all processes
    processes = []

    # Start each script in a separate process
    for script in scripts:
        p = multiprocessing.Process(target=run_script, args=(script,))
        p.start()
        processes.append(p)

    # Wait for all processes to complete
    for p in processes:
        p.join()

    print("All scripts have completed.")