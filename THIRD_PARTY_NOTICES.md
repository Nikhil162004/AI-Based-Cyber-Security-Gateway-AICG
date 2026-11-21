# Third-Party Notices and Licenses

The **AI-Based Cyber Security Gateway for Industry 4.0 (AICG)** project incorporates,
depends upon, or interfaces with several open-source third-party software packages and
simulation frameworks. This document details the verified licensing, provenance, and
copyright notices for these third-party components in compliance with their respective
license terms.

---

## 1. Simulation Frameworks & Network Tools

| Component | Upstream Project / Author | License | Description / Purpose |
| :--- | :--- | :--- | :--- |
| **NS-3 (ns-3.48)** | The ns-3 project / INRIA & contributors | **GNU GPLv2** | Discrete-event network simulator used to simulate multi-node IIoT network topologies and generate benchmark DDoS traffic traces. |
| **Contiki-NG & Cooja** | SICS / Contiki-NG Development Team | **BSD-3-Clause** | 6LoWPAN mote operating system and Cooja network simulator utilized for generating low-power wireless telemetry logs. |

---

## 2. Core Web & Gateway Runtime Dependencies

| Package | Version | Author / Organization | License (SPDX) |
| :--- | :--- | :--- | :--- |
| **Flask** | 3.1.3 | Pallets Projects | BSD-3-Clause |
| **dpkt** | 1.9.8 | Dug Song <dugsong@monkey.org> and contributors | BSD-3-Clause |
| **Werkzeug** | 3.1.8 | Pallets Projects | BSD-3-Clause |
| **Jinja2** | 3.1.6 | Pallets Projects | BSD-3-Clause |
| **MarkupSafe** | 3.0.3 | Pallets Projects | BSD-3-Clause |
| **itsdangerous** | 2.2.0 | Pallets Projects | BSD-3-Clause |
| **Click** | 8.4.2 | Pallets Projects | BSD-3-Clause |
| **Blinker** | 1.9.0 | Pallets Projects | MIT |

---

## 3. Data Science & Machine Learning Dependencies

| Package | Version | Author / Organization | License (SPDX) |
| :--- | :--- | :--- | :--- |
| **scikit-learn** | 1.9.0 | scikit-learn developers | BSD-3-Clause |
| **NumPy** | 2.5.2 | NumPy Developers | BSD-3-Clause |
| **SciPy** | 1.18.0 | SciPy Developers | BSD-3-Clause |
| **Joblib** | 1.5.3 | Joblib developers | BSD-3-Clause |
| **Pandas** | 3.0.5 | PyData / Pandas Developers | BSD-3-Clause |
| **Matplotlib** | 3.11.1 | Matplotlib Development Team | PSF-based / Permissive |
| **Pillow** | 12.3.0 | Alex Clark and Contributors | HPND |
| **Threadpoolctl**| 3.6.0 | scikit-learn developers | BSD-3-Clause |
| **Packaging** | 26.3 | Donald Stufft and packaging devs | Apache-2.0 OR BSD-2-Clause |
| **python-dateutil**| 2.9.0.post0 | Gustavo Niemeyer and contributors | Apache-2.0 OR BSD-3-Clause |
| **six** | 1.17.0 | Benjamin Peterson | MIT |
| **pyparsing** | 3.3.2 | Paul McGuire | MIT |
| **contourpy** | 1.3.3 | ContourPy Developers | BSD-3-Clause |
| **cycler** | 0.12.1 | Matplotlib Development Team | BSD-3-Clause |
| **kiwisolver** | 1.5.0 | The Kiwi Solver Developers | BSD-3-Clause |
| **fonttools** | 4.63.0 | Just van Rossum et al. | MIT |
| **narwhals** | 2.25.0 | Narwhals Developers | MIT |

---

## 4. Test & Verification Dependencies

| Package | Version | Author / Organization | License (SPDX) |
| :--- | :--- | :--- | :--- |
| **pytest** | 9.1.1 | Holger Krekel and pytest developers | MIT |
| **pluggy** | 1.6.0 | Holger Krekel and pytest developers | MIT |
| **typeguard** | 4.6.0 | Alex Grönholm | MIT |
| **anyio** | 4.15.1 | Alex Grönholm | MIT |

---

## 5. Front-End Assets & User Interface Architecture

- **Typography**: Uses modern system native font stacks (`system-ui`, `-apple-system`, `Segoe UI`, monospace tabular numerals). No third-party web font files are downloaded, bundled, or served.
- **Iconography**: All interface icons are pure inline SVG elements custom-designed for this application. No third-party icon fonts or icon libraries (such as FontAwesome or Material Icons) are imported.
- **Client-Side Runtime**: Built entirely using standard Vanilla ECMAScript 6, native DOM APIs, HTML5 Canvas, and native Server-Sent Events (SSE). No third-party JavaScript frameworks or remote Content Delivery Networks (CDNs) are loaded at runtime.

---

## 6. License Text Summaries and References

### BSD-3-Clause License Summary
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the copyright notice, this list of conditions, and the disclaimer are retained. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission. (Applicable to dpkt: Copyright (c) 2004 Dug Song <dugsong@monkey.org>; Flask, scikit-learn, NumPy, and Joblib).

### MIT License Summary
Permission is hereby granted, free of charge, to any person obtaining a copy of this software to deal in the Software without restriction, subject to retaining the copyright and permission notice.

### GNU General Public License v2 (GPLv2) Summary
Software distributed under the GPLv2 permits copying, modification, and redistribution provided that all distributed copies, modifications, and derivative works carry the prominent notices and are also licensed under the terms of the GNU GPLv2. Complete source code must be made available when binaries are distributed.


---

## 7. Clarification on Excluded Project Assets (Datasets & Models)

The research datasets, raw PCAP packet traces, feature CSV files in `backend/dataset/`, and the
pre-trained machine learning model weights in `backend/models/` are original research outputs of
the author (JAYDEEP JOTIRAM MULIK).

- They are **NOT** third-party open-source components.
- They are **NOT** covered by the root MIT License.
- They are **NOT** released under CC0, CC-BY, or any permissive open-source license.
- All rights are reserved by the copyright holder, and no additional reuse or redistribution
  permissions are granted.
