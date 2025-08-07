# AWS CloudTrail Log Analyzer

A Python tool that automatically downloads and analyzes AWS CloudTrail logs to flag suspicious behavior, including:
- Console logins without MFA (Multi Factor Authentication)
- AssumeRole events
- Access from unusual IP addresses

This project showcases my growing experience in cloud security, automation, and AWS services.

---

## What It Does

- **Fetches CloudTrail logs** from an S3 bucket (automatically created when CloudTrail is enabled)
- **Extracts** `.json.gz` log files and parses their content
- **Analyzes** each event for suspicious patterns
- **Generates a report** (`suspicious_report.txt`) with details on any risky activity found
- **Looks up IP geolocation** for login events to identify unusual access patterns

---

## What I Learned

- Using **AWS CLI** and configuring IAM access
- Automating S3 interactions with **Boto3**
- Parsing and filtering structured **CloudTrail logs**
- Writing meaningful detection logic
- Integrating **IP geolocation APIs** (ipinfo.io)
- Writing to local files for automated reporting

---

## 📂 Project Steps

This project was designed to automate the detection of suspicious events in AWS CloudTrail logs using Python. Below are the key steps I took to build and test the tool.

---

### 1️. Configure AWS CLI and Create CloudTrail

- Used `aws configure` to link the AWS CLI with my IAM user's credentials.
- Created a new CloudTrail trail to continuously log account activity.
- Verified that logs were being written to an S3 bucket.

---

### 2️. Develop Python Script to Process Logs

- Used `boto3` to connect to the S3 bucket and download the latest `.gz` CloudTrail log file.
- Decompressed and parsed the JSON log for analysis.
- <img width="952" height="280" alt="Log Extracted to latest_log" src="https://github.com/user-attachments/assets/c8bce9e0-f0ec-485c-ab8d-2648d8728236" />

---

### 3️. Analyze for Suspicious Events

The script flags:
- Console logins with **no MFA**
- API calls to services like `lambda`, `iam`, etc. from **unfamiliar IPs**
- Root account usage
- Any activity from **non-US IPs** (using IP geolocation via `ipinfo.io`)
- <img width="1131" height="472" alt="SUS ACTIVITY EXAMPLE" src="https://github.com/user-attachments/assets/696a02fc-6ce3-406d-ab77-d0562b5982e4" />

---

### 4️. Write Results to Text File

- Analysis results are written to a `suspicious_events_report.txt` file for easy review or alerting.
- If no issues are found, the message `No suspicious events found.` is returned.
- <img width="1082" height="410" alt="BEST NO SUS FOUND" src="https://github.com/user-attachments/assets/3b866d97-4edf-47f6-ba48-57cc4189ceae" />

---

### 5️. Test with Custom Log

- Created a simulated CloudTrail log with known suspicious activity to verify the detection logic.
- Confirmed that the script correctly identified the anomalies.
- <img width="632" height="282" alt="SUS JSON" src="https://github.com/user-attachments/assets/07b9cac6-78e4-4784-b4ae-19fcf8e64daf" />

---

This shows how Python can be used to monitor AWS environments for potential security risks. A key concept in cloud security automation.


---

##  Tools & Services

| Category     | Tools / Services               |
|--------------|-------------------------------|
| Cloud        | AWS CloudTrail, S3, IAM       |
| Programming  | Python, Boto3, JSON, gzip     |
| Security     | IAM auditing, MFA detection   |
| APIs         | ipinfo.io for geolocation     |

---

## 📂 File Structure

### CloudTrail-Log-Analyzer 

- [analyzer.py](https://github.com/sudo-JohnP/CloudTrail-Log-Analyzer/blob/main/analyzer.py) -- Main script to fetch, extract, analyze logs
- [test_analyzer.py](https://github.com/sudo-JohnP/CloudTrail-Log-Analyzer/blob/main/test_analyzer.py) -- Script to run test_log.json (includes fake suspicious event)
- [test_log.json](https://github.com/sudo-JohnP/CloudTrail-Log-Analyzer/blob/main/test_log.JSON) -- Purposefully Suspicious CloudTrail log for testing (With sensitive information replaced with 'REPLACETHIS')  
- README.md 
