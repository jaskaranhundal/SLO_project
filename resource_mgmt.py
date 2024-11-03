import sqlite3
import re
import socket


def init_db():
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    # Create tables for ICMP and HTTP components
    c.execute('''CREATE TABLE IF NOT EXISTS ICMP (
                    id INTEGER PRIMARY KEY, 
                    address TEXT UNIQUE, 
                    active INTEGER
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS HTTP (
                    id INTEGER PRIMARY KEY, 
                    url TEXT UNIQUE, 
                    protocol TEXT, 
                    port INTEGER, 
                    active INTEGER
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS UptimeViolationStatus (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER,
                    protocol TEXT,
                    violations_status BLOB,
                    uptime_percent REAL,

                    FOREIGN KEY(component_id) REFERENCES ICMP(id) 
                    ON DELETE CASCADE,
                    FOREIGN KEY(component_id) REFERENCES HTTP(id) 
                    ON DELETE CASCADE
                )''')
    conn.commit()
    conn.close()


def is_valid_ip(ip):
    # Validate IP address using a regex
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip) is not None


def is_valid_domain(domain):
    # Validate domain name using a regex
    pattern = re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    return pattern.match(domain) is not None


def add_icmp_component():
    address = input("Enter IP address or domain name to monitor: ").strip()

    if not (is_valid_ip(address) or is_valid_domain(address)):
        print("Invalid IP address or domain name. Please try again.")
        return

    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO ICMP (address, active) VALUES (?, 1)", (address,))
        conn.commit()

        c.execute("SELECT id FROM ICMP WHERE address = ?",(address,))
        id=c.fetchone()[0]
        c.execute("INSERT INTO UptimeViolationStatus (component_id,protocol,violations_status) VALUES (?,?,0)",(id,"ICMP",))
        conn.commit()
        print(f"ICMP component added: {address}")
    except sqlite3.IntegrityError:
        print("Error: Component already exists.")
    conn.close()

1
def add_http_component():
    domain = input("Enter domain name to monitor (e.g., example.com): ").strip()

    if not (is_valid_ip(domain) or is_valid_domain(domain)):
        print("Invalid IP address or domain name. Please try again.")
        return

    protocol = input("Enter protocol (HTTP or HTTPS (defalut) ): ").strip().upper()

    if protocol not in ['HTTP', 'HTTPS', "80","443", ""]:
        print("Invalid protocol. Please enter HTTP or HTTPS.")
        return

    # Determine the default port based on the protocol
    port = input(f"Enter port (default is {'80' if protocol == 'HTTP' else '443'}): ").strip()
    if port == "":
        port = 80 if protocol == 'HTTP' else 443

    try:
        port = int(port)  # Validate port as an integer
    except ValueError:
        print("Invalid port number. Please enter a numeric value.")
        return

    # Build the base URL
    if (protocol == "" or protocol=="https" or protocol=="443" or protocol=="HTTPS" ):
        base_url = f"{"https"}://{domain}"
        protocol="https"
    elif (protocol == "80" or protocol=="http" or protocol=="HTTP" ):
        base_url = f"{"http"}://{domain}"
        protocol = "http"


    else:
        print("Invalid protocol")
        add_http_component()

    # Append port if it's not the default for the protocol
    if (protocol == "80" or protocol=="http" or protocol=="HTTP" and port != 80) or (protocol == "" or protocol=="https" or protocol=="443" or protocol=="HTTPS" and port != 443):
        base_url += f":{port}"

    # Optionally add a URL path
    path = input("Enter URL path (optional, e.g., /api/v1): ").strip()
    if path:
        if not path.startswith('/'):
            path = '/' + path  # Ensure path starts with a forward slash
        base_url += path

    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO HTTP (url, protocol, port, active) VALUES (?, ?, ?, 1)",
                  (base_url, protocol, port))
        conn.commit()

        c.execute("SELECT id FROM HTTP WHERE url = ?", (base_url,))
        id = c.fetchone()[0]
        c.execute("INSERT INTO UptimeViolationStatus (component_id,protocol,violations_status) VALUES (?,?,0)", (id, protocol,))

        conn.commit()
        print(f"HTTP/HTTPS component added: {base_url}")
    except sqlite3.IntegrityError:
        print("Error: Component already exists.")
    conn.close()


def view_components():
    print("\n--- View Components ---")
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()

    # Display ICMP components
    print("ICMP Components:")
    c.execute("SELECT id, address FROM ICMP WHERE active = 1")
    for row in c.fetchall():
        print(f"ID: {row[0]}, Address: {row[1]}")

    # Display HTTP/HTTPS components
    print("\nHTTP/HTTPS Components:")
    c.execute("SELECT id, url, protocol, port FROM HTTP WHERE active = 1")
    for row in c.fetchall():
        print(f"ID: {row[0]}, URL: {row[1]}, Protocol: {row[2]}, Port: {row[3]}")

    conn.close()


def delete_component():
    print("\n--- Delete Component ---")
    print("\n--- Component Management Menu ---")
    print("1. Delete ICMP Component (IP address or domain)")
    print("2. Delete HTTP/HTTPS Component (URL)")
    print("3. Main Menu")
    print("4. Exit")

    choice = input("Select an option: ").strip()

    if choice == '1':
        component_id = input("Enter component ID to delete: ").strip()
    elif choice == '2':
        component_id = input("Enter component ID to delete: ").strip()
    elif choice == '3':
        main_menu()
        return  # Exit the delete_component function after calling main_menu

    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()

    if choice == '1':
        c.execute("DELETE FROM ICMP WHERE id = ?", (component_id,))
    elif choice == '2':
        c.execute("DELETE FROM HTTP WHERE id = ?", (component_id,))
    else:
        print("Invalid component type.")
        conn.close()
        return

    conn.commit()
    conn.close()
    print("Component deleted.")


def main_menu():
    init_db()
    while True:
        print("\n--- Component Management Menu ---")
        print("1. Add ICMP Component (IP address or domain name)")
        print("2. Add HTTP/HTTPS Component (Domain)")
        print("3. View Components")
        print("4. Delete Component")
        print("5. Exit")

        choice = input("Select an option: ").strip()

        if choice == '1':
            add_icmp_component()
        elif choice == '2':
            add_http_component()
        elif choice == '3':
            view_components()
        elif choice == '4':
            delete_component()
        elif choice == '5':
            print("Exiting Component Management.")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == '__main__':
    main_menu()
