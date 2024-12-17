import re
import json
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from collections import defaultdict

# Output file paths
LOG_PATH = "server_logs.txt"
FAILED_ATTEMPTS_PATH = "failed_attempts.json"
LOG_REPORT_PATH = "log_report.txt"
CSV_REPORT_PATH = "log_report.csv"
THREAT_IPS_PATH = "threat_ips.json"
SECURITY_DATA_PATH = "security_data_combined.json"

# Step 1: Extract relevant information from the logs
def extract_log_data(log_file_path):
    log_entries = []
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/.*?" (\d+) (\d+)', line)
                if match:
                    ip_address, timestamp, request_method, endpoint, response_code, _ = match.groups()
                    log_entries.append((ip_address, timestamp, request_method, response_code))
        print(f"{len(log_entries)} log entries parsed.")
        return log_entries
    except Exception as error:
        print(f"Error parsing logs: {error}")
        return []

# Step 2: Analyze failed login attempts
def identify_failed_logins(log_entries):
    failed_logins = defaultdict(int)
    for ip_address, _, _, status_code in log_entries:
        if status_code.startswith("40"):  # Failed status codes (e.g., 401, 403, 404)
            failed_logins[ip_address] += 1
    return {ip_address: count for ip_address, count in failed_logins.items() if count >= 5}

# Step 3: Save failed login attempts to JSON and TXT files
def store_failed_logins(failed_logins_data):
    # Save failed logins in JSON format
    with open(FAILED_ATTEMPTS_PATH, 'w') as json_file:
        json.dump(failed_logins_data, json_file, indent=4)
    print(f"Failed login data stored in {FAILED_ATTEMPTS_PATH}.")

    # Save failed login attempts to TXT file
    with open(LOG_REPORT_PATH, 'w') as txt_file:
        txt_file.write("Failed login attempts:\n")
        for ip_address, attempts in failed_logins_data.items():
            txt_file.write(f"{ip_address}: {attempts} failed attempts\n")
    print(f"Log analysis saved in {LOG_REPORT_PATH}.")

# Step 4: Write parsed log data to a CSV file
def save_log_data_to_csv(log_entries):
    with open(CSV_REPORT_PATH, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP Address", "Timestamp", "HTTP Method", "Response Code"])
        for ip_address, timestamp, request_method, response_code in log_entries:
            writer.writerow([ip_address, timestamp, request_method, response_code])
    print(f"Log data saved in {CSV_REPORT_PATH}.")

# Step 5: Extract threat intelligence data (IP addresses and descriptions)
def fetch_threat_intelligence_data(url):
    try:
        # Set up Chrome WebDriver
        driver = webdriver.Chrome()

        # Open the URL and extract threat intelligence data
        driver.get(url)

        # Extract rows from the threat intelligence table
        rows = driver.find_elements(By.XPATH, "//table//tr")
        threat_data = {}

        # Iterate through each row to extract IP and description
        for row in rows[1:]:  # Skip the header row
            cols = row.find_elements(By.TAG_NAME, "td")
            if len(cols) >= 2:
                ip_address = cols[0].text.strip()
                description = cols[1].text.strip()
                threat_data[ip_address] = description

        driver.quit()

        if threat_data:
            return threat_data
        else:
            print("No threat IP addresses found.")
            return {}

    except Exception as error:
        print(f"Error: {error}")
        return {}

# Step 6: Match login attempts with threat IPs
def match_threat_data(log_entries, threat_data):
    matched_threats = {}
    for ip_address, timestamp, request_method, response_code in log_entries:
        if ip_address in threat_data:
            matched_threats[ip_address] = {
                "timestamp": timestamp,
                "method": request_method,
                "response_code": response_code,
                "description": threat_data[ip_address]
            }
    return matched_threats

# Step 7: Extract threat descriptions for matched IPs
def extract_threat_descriptions(matched_threats):
    threat_info = {}
    for ip_address, data in matched_threats.items():
        threat_info[ip_address] = data["description"]
    return threat_info

# Step 8: Combine failed logins and matched threat data
def merge_security_data(failed_logins_data, matched_threats_data):
    combined_data = {
        "failed_logins": failed_logins_data,
        "matched_threats": matched_threats_data
    }
    with open(SECURITY_DATA_PATH, 'w') as json_file:
        json.dump(combined_data, json_file, indent=4)
    print(f"Combined security data saved in {SECURITY_DATA_PATH}.")

# Main function to execute all steps
def run():
    # Parse log data
    log_entries = extract_log_data(LOG_PATH)
    if not log_entries:
        print("Log data could not be parsed. Exiting.")
        return

    # Analyze failed login attempts
    failed_logins_data = identify_failed_logins(log_entries)
    if failed_logins_data:
        store_failed_logins(failed_logins_data)
    else:
        print("No IP addresses with more than 5 failed login attempts found.")

    # Write parsed log data to CSV
    save_log_data_to_csv(log_entries)

    # Fetch threat intelligence data
    threat_url = "http://127.0.0.1:5500/"
    threat_data = fetch_threat_intelligence_data(threat_url)

    # Match login attempts with threat data
    matched_threats_data = match_threat_data(log_entries, threat_data)
    with open(THREAT_IPS_PATH, "w") as json_file:
        json.dump(matched_threats_data, json_file, indent=4)
        print(f"Matched threat IPs saved in {THREAT_IPS_PATH}.")

    # Merge failed logins and matched threat data into a single file
    merge_security_data(failed_logins_data, matched_threats_data)

# Execute the main function if the script is run directly
if __name__ == "__main__":
    run()
