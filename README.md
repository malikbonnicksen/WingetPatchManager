# WingetPatchManager
PowerShell script that automatically installs itself as a scheduled task and keeps your system software up to date.
On each user logon, it collects a fresh list of installed applications (both Winget and Chocolatey), checks them against the latest CVE data from the CISA Known Exploited Vulnerabilities (KEV) and NVD (National Vulnerability Database) feeds, and silently updates any affected packages.
Designed for unattended operation with detailed logging, retry logic, and self-maintaining package mappings.
