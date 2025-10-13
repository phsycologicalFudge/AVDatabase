ColourSwift Data Handling Overview

Last updated: October 2025
Owner: ColourSwift Ltd (United Kingdom)

1. General Principle

ColourSwift operates a single application, CS Secure Files, designed for offline privacy and complete user control. The app contains no analytics, advertisements, tracking SDKs, or telemetry components.
All processing occurs locally on the user’s device unless the user explicitly initiates an update or future cloud sync.

2. Local Processing
File scans, threat detection, and storage analysis are performed entirely on-device.
The antivirus engine relies on the locally stored encrypted definitions (defs.vxpack).
No filenames, file contents, or behavioural data are transmitted to ColourSwift or any third party.

3. Network Connections
The app connects to the internet only when the user triggers an update check to download the regular database updates.
Update requests go exclusively to this repo (and in the future, official ColourSwift servers) over secure HTTPS channels.
No personal identifiers or usage statistics are included in these requests.

4. Permissions
ColourSwift Secure Files requests only the permissions necessary to scan and manage files chosen by the user.
It never accesses contacts, messages, call logs, location data, or similar personal information.

5. Logging
There is no logging performed by the app.

6. Data Retention
The app does not create online accounts and stores no personal data on ColourSwift servers.
Uninstalling the app removes all associated data and virus definitions.

7. Future Cloud Integration
ColourSwift plans to introduce ColourSwift Cloud, a complementary service providing optional encrypted storage and backups.
When launched, all cloud-stored content will be protected using enterprise-grade, end-to-end encryption.
Encryption keys will remain solely under the user’s control, ensuring that neither ColourSwift Ltd nor its infrastructure providers can view user files.
Offline operation will remain fully supported for users who prefer not to use the cloud.

8. User Control
Every function of ColourSwift Secure Files can operate offline.
Users retain complete ownership and control of their data at all times.

9. Contact
For privacy or data-protection inquiries:
Email: support@colourswift.com
