# BOTsv3-comp-3010
Github for Henry McConville comp 3010 assignment on the splunk BOTsv3 database

Introduction
This report details a forensic investigation into the Frothly food and beverage corporation, utilising the Splunk Boss of the SOC (BOTSv3) dataset. The scope of this analysis focuses on the hybrid infrastructure, bringing cloud assets and on-premises endpoints. The key telemetry sources include:
-	AWS: cloudtrial and S3 access logs track identity management and storage exposures.
-	Windows: WinHostMon logs to analyse physical system configurations and hardware-level persistence.

The primary objective is to reconstruct the attack lifecycle. Specifically, this investigation aims to:
-	Identify any vulnerabilities.
-	Assess the impact of the damage done.
-	Provide a recovery roadmap to heal and make the environment stronger.

This investigation is limited to a small part of the BOTSv3 dataset, mainly activity around and related to the user bstoll. It is assumed that all the logs provided in the Splunk index are authentic and that the timestamps are synchronised across both AWS and Windows environments to allow for accurate chronological correlation. And certain parts of the dataset requires specific add-ons to function.

SOC Roles & Incident Handling Reflection

Installation & Data Preparation
Screenshots of splunk and dataset installation on vm, add what you can word wise

Guided Questions


Conclusions

References
