# Security Monitoring with Splunk

## Project Overview

This project simulates the role of a Tier 1 SOC Analyst using Splunk as the primary Security Information and Event Management (SIEM) platform.

The project was conducted in a controlled virtual lab environment using Kali Linux, Splunk Enterprise, and the BOTS v3 dataset. The objective was to analyse multi-source security logs, identify anomalies, and investigate security incidents within a simulated hybrid enterprise environment.

The investigation covered user activity, AWS cloud activity, cloud storage misconfigurations, malicious file uploads, cryptocurrency-mining activity, and endpoint anomalies.

## Objectives

The main objectives of this project were to:

- Detect unauthorized access attempts and misconfigurations
- Investigate malicious uploads to cloud storage
- Identify potentially compromised endpoints
- Correlate logs across multiple sources
- Analyse security events using Splunk
- Document investigation findings and supporting evidence

## Tools & Technologies

- Splunk Enterprise
- Kali Linux
- Splunk Search Processing Language (SPL)
- BOTS v3 Dataset

## Data Sources

The BOTS v3 dataset contained logs from multiple sources, including:

- AWS CloudTrail
- Office 365
- Firewall traffic
- Sysmon
- Antivirus / endpoint security
- DNS queries

## Methodology

The project followed a basic SOC investigation process:

1. Installed Splunk Enterprise on a Kali Linux virtual machine.
2. Loaded the BOTS v3 dataset into the Splunk instance.
3. Restarted Splunk to ensure the dataset was properly indexed.
4. Confirmed access to the dataset using Splunk search.
5. Analysed relevant security events using SPL queries.
6. Correlated events from multiple sources to identify activity and patterns.
7. Documented findings using Splunk results and screenshots.

The dataset was initially verified using:

```spl
index=botsv3 earliest=0
```

## Investigations

### 1. IAM Users Accessing AWS Services

The investigation identified the following IAM users:

- `bstoll`
- `btun`
- `splunk_access`
- `web_admin`

**Splunk query:**

```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats count by userIdentity.userName
```

### 2. Processor Number on Web Servers

The processor identified was:

**E5-2676 v3**

**Splunk query:**

```spl
index=botsv3 sourcetype=hardware "CPU_TYPE"
| rex "CPU_TYPE\s+(?<Processor>.+)"
| stats values(processor)
```

### 3. Event ID of S3 Bucket Public Access

The investigation identified the following event ID:

**ab45689d-69cd-41e7-8705-5350402cf7ac**

**Splunk query:**

```spl
index=botsv3 sourcetype="aws:cloudtrail" "PutBucketAcl"
| table _time userIdentity.arn eventName requestParameters.bucketName eventID
| sort _time
```

### 4. Publicly Accessible S3 Bucket

The publicly accessible S3 bucket was identified as:

**Frothlywebcode**

**Splunk query:**

```spl
index=botsv3 sourcetype="aws:cloudtrail"
eventID="ab45689d-69cd-41e7-8705-5350402cf7ac"
| table requestParameters.bucktName
```

### 5. Uploaded Text File

The investigation identified the uploaded text file:

**OPEN_BUCKET_PLEASE_FIX.txt**

**Splunk query:**

```spl
index=botsv3 "frothlywebcode" ".txt"
| table _time, _raw
```

### 6. Uploaded .tar.gz File

The first successful `.tar.gz` upload identified had a size of:

**3,057,116 bits**, which was converted to **2.92 MB**.

**Splunk query:**

```spl
index=botsv3 "REST.PUT.OBJECT" frothlywebcode ".tar.gz"
```

### 7. Cryptocurrency Mining Endpoint

The short hostname of the endpoint associated with cryptocurrency-mining activity was:

**mars**

The investigation searched for indicators including:

- `xmr`
- `monero`
- `crypto`
- `minerd`
- `xmrig`

**Splunk query:**

```spl
index=botsv3 ("xmr" OR "monero" OR "crypto" OR "minerd" OR "xmrig")
```

### 8. Endpoint Running a Different Windows Edition

The investigation identified the host as:

**SEPM**

**Splunk query:**

```spl
index=botsv3 host=SEPM sourcetype=WinEventLog:Security OR
sourcetype=WinEventLog:Setup
| rex field=Message "(?i)(?<windows_info>windows[^\r\n]*)"
| Stats values(windows_info) as windows_info by host
```

## Key Findings

The investigation demonstrated Splunk's ability to correlate incidents across multiple sources of security logs.

Key observations included:

- IAM access activity that highlighted potential insider-threat concerns.
- An S3 bucket misconfiguration that resulted in public accessibility.
- Malicious or suspicious file uploads to cloud storage.
- Cryptocurrency-mining activity associated with an endpoint.
- An endpoint running a different Windows edition, demonstrating the importance of baseline monitoring.

The project highlighted core SOC responsibilities including log monitoring, event correlation, and incident reporting.

Further forensic investigation would be required for escalation.

## Skills Demonstrated

- SIEM monitoring
- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- Log analysis
- Event correlation
- Security event investigation
- AWS CloudTrail analysis
- Cloud security monitoring
- Endpoint monitoring
- Threat detection
- Incident reporting
- SOC Analyst workflow

## Conclusion

This project successfully simulated Tier 1 SOC Analyst duties within a hybrid cloud environment using Splunk.

Multiple security events were investigated, including IAM activity, cloud misconfigurations, malicious uploads, cryptocurrency-mining activity, and endpoint anomalies.

The project demonstrated how Splunk can be used to analyse and correlate security events from multiple sources to support security monitoring and incident investigation.

## Future Improvements

Potential improvements identified during the project include:

- Automation using SOAR tools
- Development of custom correlation searches
- Integration of Kubernetes logs for broader monitoring

## Project Report

The complete project report is available below:

[View the full project report](./splunk-security-monitoring-report.pdf)

## Author

**Aisha Jimoh**

Cybersecurity | Aspiring SOC Analyst
