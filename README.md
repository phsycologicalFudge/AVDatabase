# ColourSwift AVDatabase

## Overview

The **ColourSwift AVDatabase** repository contains the encrypted virus-definition package and supporting binaries used by the **ColourSwift AV+ Engine**, the offline antivirus engine powering *CS Secure Files* and future ColourSwift security products.
This repository exists to distribute verified database updates and signed APK releases for manual installation from the official ColourSwift website.

---

## Repository Structure

**defs.vxpack**

Encrypted virus-definition file. Contains curated metadata, hash records, and heuristic rules used by the ColourSwift AV+ Engine to identify and classify threats.

**defs_key.bin**

Encrypted key file used internally by the engine to decrypt and authenticate the contents of `defs.vxpack`. This file is unique to the engine and cannot be used independently.

**/releases/**

Contains signed APK builds of ColourSwift Secure Files for manual download. Builds are organised by architecture (for example, `arm64-v8a`, `armeabi-v7a`, or `x86_64`).

---

## Purpose

The virus database and key binary together form the definition core of the ColourSwift AV+ Engine.
They enable:

- Offline detection through hash, pattern, and heuristic scanning.
- Secure verification of database integrity prior to load.
- Local updates distributed through the official ColourSwift release channel.

Both files are encrypted and intended for use exclusively within ColourSwift applications.

---

## Manual Installation

Users may manually download APK releases from this repository when directed from the official ColourSwift website.
To install safely:

1. Identify the correct APK for your device architecture.
2. Download the APK directly from the latest release folder.
3. Ensure that “Install unknown apps” is enabled for the relevant application on your device.
4. Install the APK normally. All releases are digitally signed and verified by ColourSwift.

---

## License and Usage Restrictions

Copyright © 2025 ColourSwift.
All rights reserved.
The contents of this repository are proprietary and confidential. Redistribution, modification, reverse engineering, or derivative use of any file or binary without written permission from ColourSwift Technologies is strictly prohibited.
These files are intended solely for integration with ColourSwift products. Any attempt to extract, decrypt, or repurpose the database or binaries outside of authorised software constitutes a breach of copyright and intellectual property rights.

## Attribution

ColourSwift AVDatabase and ColourSwift AV+ Engine are components of the **ColourSwift Security Suite**.
Copyright © 2025 ColourSwift Ltd.
All rights reserved.
