# Cyber Incident Investigation: Splunk BOTSv3 (Frothly Breach)
**Author:** Henry McConville

**Module:** COMP3010 Security Operations & Incident Management

**Dataset:** Splunk Boss of the SOC (BOTSv3)

**Video Presentation:** https://youtu.be/RdVu0Io2J9Y

## 1. Introduction
This report documents a forensic investigation using the Boss of the SOC (BOTS) v3 dataset within a Splunk environment. The scenario involves a targeted attack against Frothly, a functional brewing company.

Objectives:
-	To investigate the BOTSv3 dataset (a blue team competition exercise simulating a Frothly breach), focusing on unauthorised S3 bucket exposure.
-	To demonstrate Splunk SPL proficiency for cross-platform correlation between AWS CloudTrail and Windows endpoint logs.
-	To apply NCSC incident management frameworks (Detect, Analyse, Respond) within a simulated SOC Tier 2 investigation.

Scope & Assumptions:
-	Scope: Analysis is limited to the BOTSv3 dataset, focusing on network traffic, endpoint logs, and web server telemetry.
-	Assumptions: It is assumed that the SOC has baseline visibility into the Frothly network. While some data normalisation (Add-ons) was finalised during the investigation, the underlying raw telemetry is assumed to be integral and accurate.


## 2. SOC Roles & Incident Handling Reflection

This report simulates the workflow of a Tier 2 SOC Analyst within the context of the BOTSv3 exercise. While a Tier 1 Analyst typically handles initial alert triage, the scope of this task requires a deep-dive investigation and cross-platform correlation to address specific security breaches. In alignment with the stated objectives, the investigative actions include identifying an unauthorised public S3 bucket, quantifying the extent of data exposure, and attributing the incident to the responsible user. These aims are achieved by linking AWS CloudTrail telemetry with Windows endpoint logs, thereby enabling a detailed reconstruction of the attack timeline across a hybrid infrastructure.

This investigation follows the NCSC Incident Management lifecycle, explicitly focusing on the Detect and Analyse stages. From a regulatory perspective in the UK, the discovery of a public S3 bucket is a high-priority incident due to potential GDPR implications regarding data exposure. By utilising Splunk to combine CloudTrail and Windows logs to identify which user created this public S3 bucket and which device was used to do so, the SOC can move beyond simple detection to gain a comprehensive understanding of the attack’s scope. The NCSC emphasises that practical analysis is a prerequisite for proportionate mitigation; by correctly identifying the root cause in the development pipeline, the SOC can avoid "blanket" shutdowns and instead focus on precise containment measures.

Applying the NCSC Incident Management lifecycle to this investigation:

**Prevention:** Fundamental control gaps existed before the breach. The absence of mandatory Multi-Factor Authentication (MFA) enabled credential-based compromise, while the lack of AWS Service Control Policies (SCPs) permitted public bucket misconfiguration. Automated secret scanning should have prevented hardcoded credentials from reaching GitHub.

**Detection:** The investigation utilised Splunk to correlate CloudTrail and Windows logs, identifying the unauthorised PutBucketAcl event and attributing it to the bstoll account.

**Response:** Immediate containment requires revoking the leaked IAM credentials and isolating the bstoll workstation (BSTOLL-L.froth.ly) to halt ongoing malicious activity.

**Recovery:** A "Lessons Learned" review must address the underlying policy breaches. Recommendations include enforcing the Principle of Least Privilege to prevent single-user misconfigurations from exposing the organisation's entire attack surface.



## 3. Installation & Data Preparation

![Figure 1: Splunk installation through tgz](Screenshots/installation_tgz.png)
*Figure 1: Extracting the Splunk tarball on Ubuntu.*

The Splunk instance was deployed on Ubuntu Linux. This choice was made to align with professional SOC infrastructure standards, prioritising resource efficiency and security. Unlike a Windows deployment, a "headless" Linux distribution significantly reduces resource overhead, ensuring that system memory is dedicated to indexing and searching rather than a GUI. From a security perspective, using a minimal Linux distro adheres to the NCSC principle of reducing the attack surface by eliminating unnecessary default applications and services.

The installation was performed using the .tgz archive. This method was selected over automated installers (such as .deb or .rpm) to provide greater control over the installation directory and file permissions. In a SOC environment, this manual approach ensures that Splunk operates within a dedicated user space, adhering to the Principle of Least Privilege by not requiring root-level access for standard operations.

![Figure 2: Splunk successfully running](Screenshots/splunk_running.png)
*Figure 2: Confirmation of splunk running.*

Figure 2 confirms that the Splunk Enterprise service has been successfully initialised and that the web interface is reachable. Validation was performed by launching the application in the browser and logging in. This step is critical in SOC preparation to ensure the SIEM is ready to ingest telemetry before any data is piped into the system.

![Figure 3: BOTSv3 successfully installed](Screenshots/botsv3_installed.png)
*Figure 3: Data Summary showing the populated botsv3 index.*

Figure 3 confirms successful ingestion of the BOTSv3 dataset, showing the directory structure containing the raw data files (LICENSE, README.txt, bin, default, lookups, and var). This validation step ensures all dataset components are present before indexing begins. Initial queries confirmed the time range (August 19-20, 2018) and presence of multiple sourcetypes (aws:cloudtrail, WinHostMon, stream:http).

During the investigation, it became necessary to install Splunk Technology Add-ons for AWS and Windows to extract structured fields from raw JSON and event data. The primary impact of these add-ons was the normalization of key fields, such as userIdentity.userName, eventName, and requestParameters, into searchable attributes, thereby transforming unstructured logs into Common Information Model (CIM) compliant data. As a result, data handling and analysis became more efficient: queries could correlate AWS CloudTrail and Windows events far more rapidly and accurately, and important security events were identified with greater reliability. 

## 4. Guided Investigation: Analysis and Timeline of Events

This investigation follows a chronological timeline, moving from a baseline audit of the Frothly environment to the identification and attribution of a specific security breach.

### BOTSv3 Questions Addressed
This investigation answers 8 of the BOTSv3 200-level questions: IAM user count, MFA status, web server identification, S3 bucket name, uploaded files, and endpoint attribution. Answers are presented chronologically through the investigation stages below.

### Stage 1: Security Posture & Baseline Audit
The investigation commenced by establishing a baseline of the environment’s identity and hardware assets to identify deviations from normal operations.

![Figure 4: List of IAM users](Screenshots/IAM_users.png)
*Figure 4: Initial audit of IAM users within the AWS environment.*

**Query:** `index=”botsv3” eventSource=”iam.amazonaws.com”`

To establish an inventory of active identities, a search was conducted on AWS CloudTrail logs in Figure 4. Identifying the total number of IAM users is a prerequisite for detecting "Dormant Accounts" or "Ghost Identities" that could be leveraged by an adversary.

![Figure 5: MFA occurrences](Screenshots/MFA_occurrences.png)
*Figure 5: Reviewing MFA logs to assess security posture.*

**Query:** `index=”botsv3” sourcetype=”aws:cloudtrail”`

An audit of Multi-Factor Authentication (MFA) usage, seen in Figure 5, revealed a Critical Control Failure. The absence of MFA across active accounts represents a violation of the NCSC's 'Identity and Access Management' principle. This vulnerability likely served as the primary entry vector for the threat actor, enabling credential-based access without a second layer of verification.

![Figure 6: Web server hardware information](Screenshots/web_server_hardware_information.png)
*Figure 6: Documentation of web server hardware specifications.*

**Query:** `index=”botsv3” sourcetype=hardware`

Figure 6 identifies the specific configuration of the cloud asset hosting the exposed code repository. Within a SOC environment, documenting the hardware profile of an affected system is a critical component of Asset Management. This ensures the investigation is accurately targeted toward the production web infrastructure and provides the necessary context to assess the potential impact of unauthorised access by the bstoll account.

---

### Stage 2: Incident Identification (The Cloud Breach)
Following the baseline audit, a specific unauthorised modification of cloud storage permissions was detected.

![Figure 7: S3 bucket Acl events](Screenshots/cloudtrial_s3_acl_events.png)
*Figure 7: The "Smoking Gun"—S3 ACL Modification.*

**Query:** `index=”botsv3” sourcetype=”aws:cloudtrail” _raw=”*PutBucketAcl*”`

Figure 7 captures the critical PutBucketAcl events. By correlating the "Opening" event (2:01:46 PM) with the "Closing" event (2:57:54 PM), the Window of Exposure was determined to be approximately 56 minutes. This chronological data is vital for assessing the potential volume of data exfiltration or unauthorised access.

![Figure 8: Account responsible username](Screenshots/source_account_username.png)
*Figure 8: Identity Attribution for user 'bstoll'.*

**Query:** `index=”botsv3” sourcetype=”aws:cloudtrail” _raw=”*PutBucketAcl*”`

Analysis of the PutBucketAcl event (Figure 8) attributes the unauthorised permission change to the IAM user bstoll. This confirms that the breach was not an external automated scan but an action performed using valid (though likely compromised) internal credentials.

![Figure 9: Name of S3 bucket that was made public](Screenshots/S3_bucket_name.png)
*Figure 9: Identification of the affected asset: 'frothlywebcode'.*

**Query:** `index=”botsv3” sourcetype=”aws:cloudtrail” _raw=”*PutBucketAcl*”`

Figure 9 pinpoints the target: the frothlywebcode S3 bucket. Given that this bucket contains production web code, the incident was escalated from a simple configuration error to a potential software supply-chain compromise.

---

### Stage 3: Impact Assessment & Endpoint Correlation
The investigation concluded by assessing the specific unauthorised activity and pivoting to the physical source of the breach.

![Figure 10: 'OPEN_BUCKET_PLEASE_FIX.txt' file uploaded to the S3 bucket](Screenshots/upoaded_file_in_s3_bucket.png)
*Figure 10: Detection of 'OPEN_BUCKET_PLEASE_FIX.txt'.*

**Query:** `index=”botsv3” sourcetype=”aws:s3:accesslogs” | search “frothlywebcode” | search "txt”`

Figure 10 reveals a file upload titled OPEN_BUCKET_PLEASE_FIX.txt. This represents an external notification (often referred to as "grey-hat" or "white-hat" reporting) in which a third party discovered the public bucket and notified the administrator. While non-malicious, it confirms that external scanners actively indexed the bucket.

![Figure 11: Other files uploaded to the S3 bucket](Screenshots/other_upoaded_files.png)
*Figure 11: Malicious payload upload - 'frothly_html_memcached.tar.gz'.*

**Query:** `index=”botsv3” sourcetype=”aws:s3:accesslogs” http_method=PUT bucket_name=frothlywebcode date_hour=14`

Unlike the previous notification, Figure 11 shows a suspicious upload of a compressed archive. While the name mimics a legitimate system file, its upload by bstoll during the window of exposure suggests a Persistence or Lateral Movement attempt. This is flagged as the primary malicious payload of the breach.

![Figure 12: Host name of endpoint](Screenshots/host_name_of_endpoint.png)
*Figure 12: Pivot from Cloud logs to Endpoint telemetry.*

**Query:** `index=”botsv3” sourcetype=”winhostmon” OS=”Microsoft Windows 1- Enterprise”`

To identify the physical origin of the bstoll activity, the investigation pivoted to Windows WinHostMon data, seen in Figure 12. This step is crucial for moving the investigation from the cloud infrastructure to the compromised physical asset.

![Figure 13: FQDN of the endpoint](Screenshots/FQDN_of_the_endpoint.png)
*Figure 13: Final confirmation of the FQDN (BSTOLL-L.froth.ly).*

**Query:** `index=”botsv3” | search BSTOLL-L`

Figure 13 provides the Fully Qualified Domain Name (FQDN) of the endpoint: BSTOLL-L.froth.ly. This identification is the final step in the "Detect and Analyse" phase, providing the SOC with the precise network location required to perform Containment—isolating the host to prevent further lateral movement.

## 5. Conclusion
### Summary of Findings
The investigation into the Frothly environment successfully identified a high-severity security breach originating from the compromised IAM account of Bud Stoll (bstoll). The timeline of events confirms a Window of Exposure of approximately 56 minutes, during which the frothlywebcode S3 bucket was transitioned to a public state via an unauthorised modification to an Access Control List (ACL).

This exposure led to the successful upload of a suspicious archive, frothly_html_memcached.tar.gz, suggesting a potential attempt at persistence or code injection within the production web environment. By pivoting from cloud-native logs to endpoint telemetry, the investigation attributed this activity to the physical workstation BSTOLL-L.froth.ly, providing the necessary intelligence for host isolation and containment.

### Key Lessons and SOC Strategy Implications
This incident highlights significant failures in Identity and Access Management (IAM) and Secure Configuration, both core pillars of the NCSC's security frameworks. Two critical control gaps enabled the compromise:
-	**The Criticality of MFA:** The primary security gap was the absence of Multi-Factor Authentication (MFA) across the AWS environment. Had MFA been enforced, the initial credential compromise would probably have been prevented, thereby preventing unauthorised cloud access entirely.
-	**The "Least Privilege" Gap:** The user bstoll possessed permissions sufficient to modify global bucket ACLs. This violates the Principle of Least Privilege (PoLP). Strategically, this incident highlights the need for SOC investment in cloud security expertise and Cloud Security Posture Management (CSPM) tooling to complement traditional network-based detection capabilities. Developer accounts should not have the authority to change the visibility of the production environment without a formal change management process or multi-party authorisation.

### Proposed Improvements for Detection and Response
Building upon the incident's key findings, the following prioritised strategic improvements are recommended to strengthen the Recovery phase and increase organisational resilience to similar breaches:
-	**Enforce MFA:** Mandate Multi-Factor Authentication for all IAM accounts with resource modification permissions, directly addressing the primary entry vector.
-	**Implement Least Privilege Controls:** Restrict developer IAM policies from modifying production bucket ACLs; deploy AWS Service Control Policies (SCPs) to prevent public bucket configurations organisation-wide.
-	**Automated Real-Time Detection:** Configure Splunk correlation searches to alert on PutBucketAcl events with public grantees (AllUsers/AuthenticatedUsers), shifting from reactive discovery to active alerting.
-	**Automated Remediation (SOAR):** Implement Security Orchestration, Automation, and Response playbooks to automatically revert unauthorised ACL changes upon detection, reducing exposure windows from minutes to seconds.
-	**Secrets Management:** Enforce strict policies against hardcoding IAM credentials in repositories, supported by automated pre-commit scanning tools (GitGuardian or AWS Secrets Manager).

## 6. References
[1] NCSC, "10 Steps to Cyber Security," 2023. [Online]. Available: https://www.ncsc.gov.uk/collection/10-steps.

[2] Splunk Inc., "Boss of the SOC Version 3 Dataset," 2019. [Online]. Available: https://github.com/splunk/botsv3.

[3] NCSC, "Incident Management Lifecycle," 2022. [Online]. Available: https://www.ncsc.gov.uk/collection/incident-management.

[4] Splunk Inc., "Search Processing Language Reference," 2024. [Online]. Available: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/.

[5] Amazon Web Services, "AWS CloudTrail User Guide," 2024. [Online]. Available: https://docs.aws.amazon.com/cloudtrail/.

