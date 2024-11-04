
import multiprocessing
import time
import logging
import requests
import sqlite3
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime

# Configure logging
logging.basicConfig(filename='http_header_slo.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze"
trust_grade = ['A', 'A+']

logging.info(f'Script start @ {datetime.now()}')
# Initialize database and create the updated table schema
def initialize_db():
    conn = sqlite3.connect('monitoring.db')
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS http_header (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT,
            hsts INTEGER DEFAULT 0,
            con_sec_pol INTEGER DEFAULT 0,
            x_con_typ_opt INTEGER DEFAULT 0,
            x_xss_pro INTEGER DEFAULT 0,
            x_frame_pro INTEGER DEFAULT 0,
            forward_secrecy INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssl_score (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            score TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS latest_http_slo_scan (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT,
            hsts INTEGER DEFAULT 0,
            x_con_typ_opt INTEGER DEFAULT 0,
            x_xss_pro INTEGER DEFAULT 0,
            forward_secrecy INTEGER DEFAULT 0,
            score TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS http_header_violation_active (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT,
            pri_violation INTEGER DEFAULT 0,
            pri_violation_count INTEGER DEFAULT 0,
            pri_violation_code blob DEFAULT NULL,
            addi_violation INTEGER DEFAULT 0,
            ext_violation INTEGER DEFAULT 0,
            ssl_violation INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()


def analyze_domain(domain):
    # Start the analysis
    parsed_url = urlparse(domain)
    domain = parsed_url.hostname
    params = {
        "host": domain,
        "all": "on"  # Include detailed information
    }

    # Request the analysis
    try:
        response = requests.get(SSL_LABS_API, params=params)

        response.raise_for_status()

        # Check the status
        analysis = response.json()

        while analysis.get("status") not in ["READY", "ERROR"]:

            time.sleep(10)
            response = requests.get(SSL_LABS_API, params=params)
            analysis = response.json()

        # Check if the analysis completed successfully
        if analysis.get("status") == "READY":

            return analysis
        else:

            raise Exception("Analysis failed or encountered an error.")
    except Exception as e:

        logging.error(f"Error checking forwordSecrecy for {domain}: {e}")


def check_forward_secrecy(analysis_data):

    fs_scores = []  # Store forward secrecy scores for each endpoint
    for endpoint in analysis_data.get("endpoints", []):
        details = endpoint.get("details", {})
        fs_score = details.get("forwardSecrecy")
        fs_scores.append(fs_score)  # Append the score to the list

    # Use Counter to find the most common score
    if fs_scores:
        score_counts = Counter(fs_scores)
        most_common_score, count = score_counts.most_common(1)[0]
    else:
        most_common_score, count = None, 0

    return most_common_score, count




def pri_violation_check(url,pri_vio_code,missing_headers):
    conn= sqlite3.connect('monitoring.db')
    c= conn.cursor()


    c.execute('select * from  http_header_violation_active where url = ?', (url,))
    cur_active_vio = c.fetchall()####get the all active violations 0 for not deactice and 1 for active

    def_val_0 = 0
    def_val_1 = 1

    if (cur_active_vio is None or cur_active_vio == []):

        if pri_vio_code != '1111':
            pri_vio_count = 1

            c.execute(
                'insert into http_header_violation_active  (url,pri_violation ,pri_violation_count , pri_violation_code,addi_violation,ext_violation,ssl_violation) values (?,?,?,?,?,?,?)',
                (url,pri_vio_count,pri_vio_count, pri_vio_code,def_val_0,def_val_0,def_val_0,))
            conn.commit()
            logging.error(f"ERROR: For url: {url} Missing headers: - {', '.join(missing_headers)}")
        else:
            def_val_0 = 0

            c.execute(
                'insert into http_header_violation_active  (url,pri_violation ,pri_violation_count , pri_violation_code,addi_violation,ext_violation,ssl_violation) values (?,?,?,?,?,?,?)',
                (url, def_val_0, def_val_0, pri_vio_code, def_val_0, def_val_0, def_val_0,))
            conn.commit()

    else:
        cur_active_vio=cur_active_vio[0]
        if cur_active_vio[5]==pri_vio_code and cur_active_vio[5] != '1111':
            pri_vio_count = 1 + cur_active_vio[4]
            c.execute("update http_header_violation_active set pri_violation_count = ? where url =?",(pri_vio_count,url))
            conn.commit()

        elif pri_vio_code == "1111" and  cur_active_vio[5] != "1111":
            c.execute("update http_header_violation_active set pri_violation_count = ?,pri_violation = ?,pri_violation_code =? where url =?",
                      (def_val_0,def_val_0,pri_vio_code, url))
            conn.commit()
            logging.info(f"Issue has been resolved for URL {url}.We are getting the all required headers.")
        elif pri_vio_code != cur_active_vio[5]:
            pri_vio_count = 1 + cur_active_vio[4]
            c.execute("update http_header_violation_active set pri_violation_count = ?, pri_violation_code =? where url =?",(pri_vio_count,pri_vio_code,url))
            conn.commit()
            logging.error(f"New issue found for url: {url} current Missing headers: - {', '.join(missing_headers)}. Ignore the earlier issue.")





        #### extended violation active and deactive

        if int(cur_active_vio[4]) >= 3 and cur_active_vio[7] == 0:  ### to active

            c.execute("update http_header_violation_active set ext_violation = ? where url =?",
                      (def_val_1, url))
            conn.commit()
            logging.error(f'Extedned violation: active for utl {url}.')

        elif int(cur_active_vio[4]) == 0 and cur_active_vio[7] == 1: ## to deactive
            c.execute("update http_header_violation_active set ext_violation = ? where url =?",
                      (def_val_0, url))
            conn.commit()
            logging.error(f'Extedned violation: deactived.Issue has been resoved for {url}.')

        if len(missing_headers)>=2 and cur_active_vio[6] == 0 and cur_active_vio[8] == 1:
            c.execute("update http_header_violation_active set addi_violation = ? where url =?",
                      (def_val_1, url))
            conn.commit()
            logging.error(f'Additional violation: active for URL {url}. More then 2 headers are missing as - {', '.join(missing_headers)} and SSL grade  is lower then A.')

        else:
            if cur_active_vio[6] == 1:

                print(len(missing_headers))
                if (len(missing_headers)<2 or cur_active_vio[8] == 0):
                    c.execute("update http_header_violation_active set addi_violation = ? where url =?",
                              (def_val_0, url))
                    conn.commit()
                    logging.error(f'Additional violation deactived for URL {url}. Issue has been resolved.')


    return


# Function to check security headers for each URL
def check_security_headers():
    headers_to_check = {
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-xss-protection',
        'x-frame-options'
    }

    while True:
        conn = sqlite3.connect('monitoring.db')
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM HTTP")
        urls = cursor.fetchall()
        conn.commit()

        for url in urls:
            url = url[0]
            hsts = con_sec_pol = x_con_typ_opt = x_xss_pro = x_frame_pro = 0  # Initialize header values
            fs = 0
            missing_headers = []
            binary_code = [0, 0, 0, 0]

            try:

                analysis_data = analyze_domain(url)

                fs_results = check_forward_secrecy(analysis_data)

                if fs_results[0] >= 1:
                    fs = 1
                    binary_code[3] = 1
                else:
                    missing_headers.append('ForwardSecrecy')

                response = requests.get(url, timeout=10)

                # Check each header and mark as 1 if found, else 0
                if 'strict-transport-security' in response.headers:
                    hsts = 1
                    binary_code[0] = 1
                else:
                    missing_headers.append('strict-transport-security')

                if 'content-security-policy' in response.headers:
                    con_sec_pol = 1

                if 'x-content-type-options' in response.headers:
                    x_con_typ_opt = 1
                    binary_code[1] = 1
                else:
                    missing_headers.append('x-content-type-options')

                if 'x-xss-protection' in response.headers:
                    x_xss_pro = 1
                    binary_code[2] = 1
                else:
                    missing_headers.append('x-xss-protection')

                if 'x-frame-options' in response.headers:
                    x_frame_pro = 1



                binary_string  = ''.join(str(bit) for bit in binary_code)

                # Insert the result into the database
                cursor.execute('''
                    INSERT INTO http_header (url, hsts, con_sec_pol, x_con_typ_opt, x_xss_pro, x_frame_pro, forward_secrecy)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (url, hsts, con_sec_pol, x_con_typ_opt, x_xss_pro, x_frame_pro, fs))

                cursor.execute('SELECT * FROM latest_http_slo_scan WHERE url = ?', (url,))
                result = cursor.fetchall()  ## last scan for each scan
                score = 0



                if result == []:
                    cursor.execute(
                        'INSERT INTO latest_http_slo_scan (url, hsts, x_con_typ_opt, x_xss_pro, forward_secrecy, score) VALUES (?, ?, ?, ?, ?, ?)',
                        (url, hsts, x_con_typ_opt, x_xss_pro, fs, score))
                else:
                    cursor.execute(
                        'UPDATE latest_http_slo_scan SET hsts = ?, x_con_typ_opt = ?, x_xss_pro = ?, forward_secrecy = ? WHERE url = ?',
                        (hsts, x_con_typ_opt, x_xss_pro, fs, url))
                conn.commit()
                #if binary_string!='1111':

                pri_violation_check(url,binary_string,missing_headers)



                conn.commit()

            except Exception as e:
                conn.commit()

                logging.error(f"Error checking headers for {url}: {e}")

            time.sleep(1)  # Repeat every 2 seconds


def getParts(url_string):
    p = urlparse(url_string)
    return [p.scheme, p.hostname, p.port]


# Function to check SSL score and forward secrecy
def check_ssl_scores():
    while True:
        conn = sqlite3.connect('monitoring.db')
        c = conn.cursor()
        c.execute("SELECT url FROM HTTP")
        urls = c.fetchall()

        ssl_results = {}

        for domain in urls:
            url = getParts(domain[0])
            url = url[1]
            logging.info(f"Checking SSL score for {url}")

            try:
                # Start the SSL Labs analysis for the domain
                response = requests.get(SSL_LABS_API, params={'host': url}, timeout=10)
                data = response.json()

                # Poll until the analysis is complete for this domain
                while data['status'] not in ['READY', 'ERROR']:
                    time.sleep(10)  # Wait before polling again
                    response = requests.get(SSL_LABS_API, params={'host': url}, timeout=10)
                    data = response.json()

                # Check if there's an error in the response
                if data['status'] == 'ERROR':
                    logging.error(f"Error analyzing {url} via SSL Labs: {data.get('statusMessage')}")
                    ssl_results[url] = {'ssl_score': data.get('statusMessage')}
                    continue

                # Extract the grade and Forward Secrecy support
                endpoints = data['endpoints'][0]
                ssl_grade = endpoints['grade']
                fs_supported = endpoints.get('details', {}).get('forwardSecrecy', False)

                # Store the results for this domain
                ssl_results[url] = {'ssl_score': ssl_grade, 'fs_supported': fs_supported}
                c.execute("INSERT INTO ssl_score (url, score) VALUES (?, ?)", (url, ssl_grade,))
                c.execute("UPDATE latest_http_slo_scan SET score = ? WHERE url = ?", (ssl_grade, domain[0],))
                conn.commit()

                # Check for violations
                c.execute("SELECT ssl_violation FROM http_header_violation_active WHERE url = ?", (domain[0],))
                current_status = c.fetchone()

                if ssl_grade not in trust_grade:
                    if current_status is None:
                        ssl_violation = 1
                        c.execute('INSERT INTO http_header_violation_active (url, ssl_violation) VALUES (?, ?)',
                                  (domain[0], ssl_violation,))
                        conn.commit()
                        logging.error(f"SSL violation for {url}. Current SSL score is {ssl_grade}")

                else:
                    if current_status and current_status[0] == 1:
                        c.execute("UPDATE http_header_violation_active SET ssl_violation = 0 WHERE url = ?", (domain[0],))
                        logging.info(f"SSL violation for {url} has been resolved. Current SSL score is {ssl_grade}")
                        conn.commit()

            except requests.RequestException as e:
                logging.error(f"Error accessing SSL Labs API for {url}: {e}")
                ssl_results[url] = {f"Error accessing SSL Labs API for {url}: {e}"}

            time.sleep(1800)  # Run every 10 seconds


# Main function to manage processes and run both tasks concurrently
if __name__ == "__main__":
    initialize_db()
    # Create processes for checking headers and SSL scores
    headers_process = multiprocessing.Process(target=check_security_headers)
    ssl_process = multiprocessing.Process(target=check_ssl_scores)
    headers_process.start()
    ssl_process.start()
    headers_process.join()
    ssl_process.join()
