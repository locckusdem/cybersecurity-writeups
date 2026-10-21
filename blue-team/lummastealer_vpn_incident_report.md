# Incident Triage Report: LummaStealer Ingress & VPN Abuse

- **Case ID:** IR-2026-VPN-LUMMA
- **Platform Source:** TryHackMe (ROOM: *Just a VPN Login*)
- **Analyst Role:** SOC Tier 1 / Tier 2 Incident Responder
- **Classification:** True Positive / Credential Exfiltration & Unauthorized Remote Access
- **Target User:** `susan.martin@probablyfine.thm` (Marketing Department)
- **Primary Malware:** LummaStealer (`Trojan:Win32/LummaStealer.PM!MTB`)
- **Severity:** High
- **Date:** October 2026

---

## 1. Executive Summary

A high-severity security alert flagged an anomalous internal VPN authentication session for user `susan.martin@probablyfine.thm` originating from public IP `37.19.201.132` (Singapore). Although corporate travel itineraries confirmed the employee was physically in Singapore attending an industry vendor conference, incident triage verified that she had not initiated this connection.

Host inspection and telemetry correlation revealed that while connected to an untrusted public Wi-Fi network at a local cafe, the user was prompted to download and install a rogue "security check" utility (`zY9sqWs.exe`). The dropped executable was identified as **LummaStealer**, which exfiltrated cached browser secrets, active session tokens, and stored VPN endpoint configurations. The adversary immediately weaponized these valid credentials to authenticate against the corporate perimeter via a commercial VPN exit node situated in the target's geographic region.

---

## 2. Attack Lifecycle & Kill Chain

```text
[ Public Wi-Fi Hotspot (Cafe) ]
              │
              ▼ (Social Engineering / Rogue Update Prompt)
[ Dropper Binary: zY9sqWs.exe ]
              │
              ▼ (LummaStealer Execution & Memory Extraction)
[ Exfiltration of Saved Browser Credentials & VPN Profiles ]
              │
              ▼ (Traffic Masquerading via ASN 212238)
[ Corporate VPN Breach from IP 37.19.201.132 ]
```

1. **Initial Access:** Drive-by social engineering prompt posing as a mandatory captive portal security check on public Wi-Fi.
2. **Execution:** User executed `zY9sqWs.exe` under standard unprivileged user context.
3. **Credential Access:** LummaStealer extracted passwords, session cookies, and stored VPN configurations from local browser vaults.
4. **Ingress Compromise:** Adversary authenticated into internal corporate assets using stolen valid credentials, obfuscating true origin via commercial VPN infrastructure.

---

## 3. Indicators of Compromise (IOCs)

### Network Artifacts

| Indicator | Type | Context / Details |
| :--- | :--- | :--- |
| `37.19.201.132` | IPv4 | Ingress VPN authentication origin; commercial VPN exit node |
| `212238` | ASN | Autonomous System Number hosting the ingress proxy node |
| `151` Domains | TLS Cluster | Infrastructure nodes sharing campaign SSL/TLS certificates |

### Endpoint & Binary Artifacts

| Attribute | Value |
| :--- | :--- |
| **File Name** | `zY9sqWs.exe` |
| **SHA-256** | `b8e02f2bc0ffb42e8cf28e37a26d8d825f639079bf6d948f8debab6440ee5630` |
| **Threat Signature** | `Trojan:Win32/LummaStealer.PM!MTB` |
| **YARA Rule Condition** | `uint16(0) == 0x5a4d and any of them` (rule authored by `kevoreilly`) |

---

## 4. Threat Intelligence & Attribution Notes

Correlated through the technical dossier *"Behind the Curtain: How Lumma Affiliates Operate"*:

- **Infrastructure Sourcing:** Affiliates consistently acquire disposable VPS infrastructure via **AnonRDP**.
- **Proxy Partnerships:** Operational tie-ins identified in early 2024 with **GhostSocks** for residential and commercial IP routing.
- **Syndicate Ecosystem:** Associated regional affiliates (including Mexican-based operators) cross-deploy mobile malware families, notably **CraxsRAT** on Android devices.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Finding |
| :--- | :--- | :--- | :--- |
| **Resource Development** | `T1583.003` | Acquire Infrastructure: Virtual Private Server | Operational backend purchased via AnonRDP |
| **Initial Access** | `T1189` | Drive-by Compromise | Malicious update prompt via public Wi-Fi hotspot |
| **Execution** | `T1204.002` | User Execution: Malicious File | Execution of dropper binary `zY9sqWs.exe` |
| **Credential Access** | `T1555.003` | Credentials from Web Browsers | LummaStealer harvesting browser vault and sessions |
| **Defense Evasion** | `T1090.003` | Proxy: Multi-hop Proxy | Tunneling traffic via GhostSocks and commercial VPN |
| **Lateral Movement** | `T1133` | External Remote Services | Corporate ingress access using stolen VPN credentials |

---

## 6. Containment & Remediation Actions

1. **Session Termination & Credential Revocation:** Immediately terminate active VPN tunnels for `susan.martin@probablyfine.thm` and revoke Kerberos/Active Directory tokens across all domain controllers.
2. **Endpoint Quarantine & Forensics:** Isolate the endpoint from all corporate networks, acquire RAM and disk images for detailed forensic analysis, and initiate a full operating system reimage.
3. **MFA Hardening:** Enforce FIDO2 hardware token authentication or out-of-band MFA verification for all remote ingress endpoints.
4. **Boundary Blocking:** Add IP `37.19.201.132` and the CIDR prefix under ASN `212238` to edge perimeter drop lists.