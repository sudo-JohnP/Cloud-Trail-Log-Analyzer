# Python script


import boto3
import gzip 
import json
from datetime import datetime
from dateutil import parser

s3 = boto3.client('s3')

bucket_name = 'put your bucket name here!' 
log_prefix = 'AWSLogs/'


def get_latest_log_file(): # function for retrieving the latest log file

    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=log_prefix)
    files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.gz')]

    if len(files) == 0:
        print("No log files found.")
        return None
    
    latest_file = sorted(files)[-1]
    print(f"Latest log file: {latest_file}")
    return latest_file
    

def download_and_extract_log(key): # function for extracting the log
    local_file = 'latest_log.json.gz'
    extracted_file = 'latest_log.json'

    s3.download_file(Bucket=bucket_name, Key=key, Filename=local_file)

    with gzip.open(local_file, 'rb') as f_in:
        with open(extracted_file, 'wb') as f_out:
            f_out.write(f_in.read())

    print(f"Log extracted to: {extracted_file}")
    return extracted_file


def analyze_events(json_file): # function that analyzes for suspicious events
    with open(json_file, 'r') as f:
        log_data = json.load(f)

    suspicious_events = []

    for record in log_data['Records']:
        event_name = record.get('eventName', '')
        user = record.get('userIdentity', {}).get('arn', 'Unknown')
        source_ip = record.get('sourceIPAddress', 'Unknown')
        time = record.get('eventTime', '')

        # Console login without MFA
        if event_name == 'ConsoleLogin':
            mfa_used = record.get('additionalEventData', {}).get('MFAUsed', 'No')
            if mfa_used != 'Yes':
                suspicious_events.append((event_name, user, source_ip, time, 'Console login without MFA'))

        # High-risk actions
        high_risk = ['DeleteTrail', 'StopLogging', 'PutBucketPolicy']
        if event_name in high_risk:
            suspicious_events.append((event_name, user, source_ip, time, 'High-risk action'))

    if not suspicious_events:
        print("No suspicious events found.")
    else:
        print("Suspicious activity detected:\n")
        for event in suspicious_events:
            print(f"[{event[3]}] {event[0]} by {event[1]} from {event[2]} ({event[4]})")


if __name__ == "__main__":
    key = get_latest_log_file()
    if key:
        local_json = download_and_extract_log(key)
        analyze_events(local_json)

