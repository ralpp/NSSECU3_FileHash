# File Hash Threat Intelligence Automator

A Python-based utility to automate bulk file hash screening against VirusTotal and AlienVault OTX to determine file reputations.

## Features
* **Multi-Platform Queries**: Simultaneously queries **VirusTotal v3** and **AlienVault OTX** for file metadata (MD5, SHA1, SHA256, and File Type).
* **Automated Verdict Logic**: Implements a detection threshold where files are classified as "Malicious" if 3 or more engines flag them, otherwise classified as "Benign".
* **API Key Rotation**: Features a rotation mechanism that cycles through multiple VirusTotal API keys every 220 entries to prevent rate-limit throttling. 
* **Dual Format Reporting**: Automatically saves processed results in both `.csv` and `.xlsx` formats for easy integration with other tools. 
