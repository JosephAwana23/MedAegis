# MedAegis 🛡️
### Enterprise Clinical XDR, Forensic Chain-of-Custody Locker & Dual-Engine AI Threat Intelligence Suite

`MedAegis` is an active-defense, standalone Python security platform engineered specifically for healthcare environments, hospital Blue Teams, and Clinical Security Operations Centers (SOCs). 

Modern healthcare facilities operate under an asymmetric threat landscape: life-critical Internet of Medical Things (IoMT) devices run on legacy firmware that cannot host kernel-level EDR agents. Furthermore, hospital networks are bound by strict federal mandates—including the **HIPAA Security Rule (45 CFR § 164.312)** and **42 CFR Part 2**—which strictly prohibit transmitting raw electronic Protected Health Information (ePHI) to external cloud analysis services. MedAegis bridges this gap through a multi-layered local sanitization and dual-engine AI pipeline.

---

## 🚀 Key Architectural Features

1. **Local Safe Harbor ePHI & Part 2 DLP Scrubber (Module 1):** Intercepts clinical text and log payloads locally, stripping out all 18 HIPAA Safe Harbor identifiers and high-sensitivity Substance Use Disorder (SUD) keywords via regular expressions *before* any metadata leaves the local enclave.
2. **Passive IoMT Network Radar (Module 2):** Sniffs network telemetry passively (NetFlow, ARP, mDNS) without active scanning probes that could crash fragile medical hardware.
3. **Shift-Aware EHR Anomaly Engine (Module 3):** Correlates Electronic Health Record (EHR) access logs with physical badge swipes and shift schedules to instantly detect "Ghost Shift" logons and mass chart scraping.
4. **Cross-Platform OS Hardening & SHA-256 FIM (Module 4):** Evaluates local endpoint compliance (Linux LUKS, Windows BitLocker, firewall states, and risky open ports) while establishing cryptographic File Integrity Monitoring (FIM).
5. **Dual-Engine AI Intelligence Core (Module 5):** Powered by **Gemini 3.8 Flash** (`thinkingLevel="low"`) for instant millisecond-level SOC priority queue triage, and **Gemini 4 Argon** (`thinkingLevel="high"`, 64K token window) for deep multi-vector threat correlation and production-ready remediation script generation.
6. **Cryptographic Forensic Locker (Module 6):** Automatically bundles volatile system state and incident metadata into a ZIP archive sealed with an immutable SHA-256 manifest for federal investigators (HHS OCR).
7. **Ransomware Canary Tripwire (Module 7):** Deploys hidden decoy ePHI files (`PATIENT_MASTER_LIST_2026_CONFIDENTIAL.xlsx`) that trip instant automated isolation upon unauthorized read/write probes.
8. **CISA/HHS Healthcare CTI Correlator (Module 8):** Cross-references live telemetry against curated Indicators of Compromise (IOCs) for healthcare threat groups (LockBit, ALPHV/BlackCat) and malicious Tor exit nodes.

---

## 📂 Repository Structure

```text
MedAegis/
├── med_aegis.py                          # The complete standalone enterprise XDR engine (Modules 1–8)
├── med_aegis_v3_report.json              # Structured JSON forensic telemetry and AI synthesis output
├── forensic_evidence/                    # Cryptographically sealed chain-of-custody bundles
│   └── medaegis_forensic_bundle_*.zip    # Zipped volatile state + .sha256.json manifest
└── PATIENT_MASTER_LIST_2026_CONFIDENTIAL.xlsx # Active ransomware canary honeytoken file