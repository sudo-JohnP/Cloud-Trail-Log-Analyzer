# Full Python Script

import boto3
import gzip 
import json
from datetime import datetime
from dateutil import parser
import requests

s3 = boto3.client('s3')

bucket_name = 'aws-cloudtrail-logs-516224964639-5ce6454d'
log_prefix = 'AWSLogs/'


def list_all_log_keys(): 
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=log_prefix)
    return [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.gz')]

def download_and_extract_log(key, index):
    local_gz = f'log_{index}.json.gz'
    local_json = f'log_{index}.json'

    s3.download_file(Bucket=bucket_name, Key=key, Filename=local_gz)

    with gzip.open(local_gz, 'rb') as f_in:
        with open(local_json, 'wb') as f_out:
            f_out.write(f_in.read())

    print(f"Extracted: {local_json}")
    return local_json


def analyze_events(json_file): 
    with open(json_file, 'r') as f:
        log_data = json.load(f)

    suspicious_events = []

    for record in log_data['Records']:
        event_name = record.get('eventName', '')
        user = record.get('userIdentity', {}).get('arn', 'Unknown')
        source_ip = record.get('sourceIPAddress', 'Unknown')
        ip_location = get_ip_location(source_ip)
        time = record.get('eventTime', '')

        if event_name == 'ConsoleLogin':
            mfa_used = record.get('additionalEventData', {}).get('MFAUsed', 'No')
            if mfa_used != 'Yes':
                suspicious_events.append((event_name, user, source_ip, time, 'Console login without MFA'))

        high_risk = ['DeleteTrail', 'StopLogging', 'PutBucketPolicy']
        if event_name in high_risk:
            suspicious_events.append((event_name, user, source_ip, time, 'High-risk action'))

    with open('suspicious_report.txt', 'w') as report:
        if not suspicious_events:
            message = "No suspicious events found."
            print(message)
            report.write(message + '\n')
        else:
            header = "Suspicious activity detected:\n\n"
            print(header)
            report.write(header)
            for event in suspicious_events:
                line = f"[{event[3]}] {event[0]} by {event[1]} from {source_ip} ({ip_location}) — {event[4]}"
                print(line)
                report.write(line + '\n')
    
    print("\nReport saved to: suspicious_report.txt")

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', 'Unknown')
            region = data.get('region', 'Unknown')
            country = data.get('country', 'Unknown')
            return f"{city}, {region}, {country}"
    except Exception as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")
    return "Unknown location"


if __name__ == "__main__":
    log_keys = list_all_log_keys()

    if not log_keys:
        print("No log files found.")
    else:
        print(f"Found {len(log_keys)} log files. Processing...\n")
        for i, key in enumerate(log_keys, start=1):
            json_file = download_and_extract_log(key, i)
            analyze_events(json_file)
