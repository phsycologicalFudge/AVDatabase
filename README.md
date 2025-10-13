ColourSwift AVDatabase
Overview

The ColourSwift AVDatabase repository contains the encrypted virus-definition package and supporting binaries used by the ColourSwift AV+ Engine, the offline antivirus engine powering CS Secure Files and future ColourSwift security products.

This repository exists to distribute verified database updates and signed APK releases for manual installation from the official ColourSwift website.

Repository Structure

defs.vxpack
Encrypted virus-definition file. Contains curated metadata, hash records, and heuristic rules used by the ColourSwift AV+ Engine to identify and classify threats.

defs_key.bin
Encrypted key file used internally by the engine to decrypt and authenticate the contents of defs.vxpack. This file is unique to the engine and cannot be used independently.

/releases/
Contains signed APK builds of ColourSwift Secure Files for manual download. Builds are organised by architecture (for example, arm64-v8a, armeabi-v7a, or x86_64).

Purpose

The virus database and key binary together form the definition core of the ColourSwift AV+ Engine.
They enable:

Offline detection through hash, pattern, and heuristic scanning.

Secure verification of database integrity before load.

Local updates are distributed through the official ColourSwift release channel.

Both files are encrypted and intended for use exclusively within ColourSwift applications.

Manual Installation

Users may manually download APK releases from this repository when directed from the official ColourSwift website.

To install safely:

Identify the correct APK for your device architecture.

Download the APK directly from the latest release folder.

Ensure that “Install unknown apps” is enabled for the relevant application on your device.

Install the APK normally. All releases are digitally signed and verified by ColourSwift.

License and Usage Restrictions

Copyright © 2025 ColourSwift Technologies.
All rights reserved.

The contents of this repository are proprietary and confidential. Redistribution, modification, reverse engineering, or derivative use of any file or binary without written permission from ColourSwift Technologies is strictly prohibited.

These files are intended solely for integration with ColourSwift products. Any attempt to extract, decrypt, or repurpose the database or binaries outside of authorised software constitutes a breach of copyright and intellectual property rights.

To ensure appropriate protection on GitHub, select “Other → Add custom license” and include the following statement:

Proprietary License (All Rights Reserved)

The ColourSwift AVDatabase and all associated files, including defs.vxpack, defs_key.bin, and APK releases, are the exclusive property of ColourSwift Technologies. Redistribution or reverse engineering is not permitted.

Do not apply permissive open-source licenses such as MIT, Apache, or GPL, as they explicitly grant redistribution rights.

Integration Notes

The definition files in this repository are tightly coupled to the ColourSwift AV+ Engine and cannot be used outside of its runtime environment. Future updates will follow a versioned naming scheme (for example, vxpack-2025-03-01) for clear release tracking.

Attribution

ColourSwift AVDatabase and ColourSwift AV+ Engine are components of the ColourSwift Security Suite.
Copyright © 2025 ColourSwift Technologies Ltd.
All rights reserved.
