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
- test_log.json -- Purposefully Suspicious CloudTrail log for testing     
- README.md 
