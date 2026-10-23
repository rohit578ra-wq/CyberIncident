"""
🚨 CyberIncident — Cyber Incident Response Triage & Management Assistant
Author: CyberIncident Security Operations Team
License: MIT
Description: Digital Incident Response (DFIR) triage assistant based on NIST SP 800-61.
             Features interactive playbooks, IOC evidence logger, timeline tracker,
             severity matrix, and executive Post-Incident Report (PIR) generator.
"""

import json
from datetime import datetime
import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="CyberIncident — Incident Response Assistant",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .cir-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #EF4444;
        margin-bottom: 0px;
    }
    .cir-subtitle {
        font-size: 1rem;
        color: #9CA3AF;
        margin-bottom: 25px;
    }
    .badge-p1 { background-color: #7F1D1D; color: #FCA5A5; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 1.1rem; }
    .badge-p2 { background-color: #7C2D12; color: #FDBA74; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 1.1rem; }
    .badge-p3 { background-color: #713F12; color: #FDE047; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 1.1rem; }
    .badge-p4 { background-color: #14532D; color: #86EFAC; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 1.1rem; }
    .stDownloadButton>button {
        width: 100%;
        background-color: #DC2626;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State for Incident Artifacts
if "iocs" not in st.session_state:
    st.session_state["iocs"] = [
        {"type": "Malicious IP", "value": "198.51.100.23", "notes": "C2 Beacon Destination"},
        {"type": "SHA-256 Hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "notes": "Dropped Ransomware Dropper Binary"}
    ]

if "timeline" not in st.session_state:
    st.session_state["timeline"] = [
        {"time": "2026-10-22 14:15", "actor": "SOC Analyst", "action": "SIEM triggered critical alert for mass file encryption on FS-01."},
        {"time": "2026-10-22 14:22", "actor": "Incident Commander", "action": "VLAN isolation enacted on 192.168.10.0/24 subnet."}
    ]

# NIST SP 800-61 Playbook Checklists by Attack Vector
PLAYBOOKS = {
    "Ransomware / Extortion": {
        "Phase 1: Identification": [
            "Identify infected endpoints and servers showing ransom extensions.",
            "Inspect honeypot file modifications and canary tokens.",
            "Extract ransomware note details, ransom address, and binary samples.",
            "Determine initial entry vector (e.g., Phishing, RDP brute force, VPN flaw)."
        ],
        "Phase 2: Containment": [
            "Physically disconnect or isolate affected network VLANs immediately.",
            "Disable compromised Active Directory user and service accounts.",
            "Block outbound C2 communications on external perimeter firewalls.",
            "Preserve memory dumps (RAM) of infected systems before power-off."
        ],
        "Phase 3: Eradication": [
            "Terminate malicious scheduled tasks, registry run keys, and startup services.",
            "Wipe and re-image all compromised operating systems from secure golden images.",
            "Validate hypervisor and virtualization backups are uncompromised and intact.",
            "Deploy endpoint detection (EDR) agents to detect lateral persistence."
        ],
        "Phase 4: Recovery": [
            "Restore systems sequentially from verified clean offline/immutable backups.",
            "Enforce mandatory password resets across all enterprise domain accounts.",
            "Monitor restored workloads under heightened security telemetry for 72 hours."
        ]
    },
    "Phishing / Business Email Compromise (BEC)": {
        "Phase 1: Identification": [
            "Extract raw email headers, sending IP, and reply-to address.",
            "Analyze malicious attachment or credential harvesting link.",
            "Search mail server message trace logs to identify all email recipients."
        ],
        "Phase 2: Containment": [
            "Purge phishing email from all recipient inboxes across the tenant.",
            "Block sender address and domain on Email Security Gateway.",
            "Revoke active browser sessions and reset credentials for users who clicked.",
            "Enforce Multi-Factor Authentication (MFA) re-registration."
        ],
        "Phase 3: Eradication": [
            "Check compromised email accounts for unauthorized mailbox forwarding rules.",
            "Review Azure AD / Google Workspace app registrations for rogue OAuth grants.",
            "Audit recent outbound emails sent from compromised mailboxes."
        ],
        "Phase 4: Recovery": [
            "Re-enable mailbox access following multi-factor reset.",
            "Send advisory security communication to affected internal personnel."
        ]
    },
    "DDoS Attack": {
        "Phase 1: Identification": [
            "Determine attack category (Volumetric UDP flood, SYN flood, or Layer 7 HTTP flood).",
            "Identify targeted IP addresses, domains, and impacted applications."
        ],
        "Phase 2: Containment": [
            "Activate Cloud DDoS Mitigation (Cloudflare, AWS Shield, Akamai).",
            "Enable aggressive rate-limiting and geo-blocking for suspicious sources.",
            "Apply upstream ISP BGP blackholing for targeted non-critical IPs."
        ],
        "Phase 3: Eradication": [
            "Filter spoofed attack packets using access control lists (ACLs).",
            "Scale backend server capacity or deploy caching reverse proxies."
        ],
        "Phase 4: Recovery": [
            "Verify steady application latency and normal user traffic patterns.",
            "Gradually loosen rate-limiting thresholds to normal baseline parameters."
        ]
    }
}


def calculate_severity(vector: str, systems_affected: int, data_impact: str, business_impact: str):
    """Calculate incident severity tier (P1 Critical down to P4 Low)."""
    score = 0
    if systems_affected >= 50:
        score += 4
    elif systems_affected >= 10:
        score += 3
    elif systems_affected >= 2:
        score += 2
    else:
        score += 1

    if data_impact == "Confidential Data Exfiltrated":
        score += 4
    elif data_impact == "Data Encrypted / Damaged":
        score += 3
    elif data_impact == "Internal Telemetry Only":
        score += 1

    if business_impact == "Complete Operations Outage":
        score += 4
    elif business_impact == "Significant Disruption":
        score += 3
    elif business_impact == "Minor Inconvenience":
        score += 1

    if score >= 10 or vector == "Ransomware / Extortion":
        return "P1 - CRITICAL", "badge-p1", "Catastrophic impact. Immediate executive escalation, legal, and crisis IR required."
    elif score >= 7:
        return "P2 - HIGH", "badge-p2", "Severe impact. Core business services impaired. Emergency response team deployed."
    elif score >= 5:
        return "P3 - MEDIUM", "badge-p3", "Moderate impact. Contained within isolated endpoints. Standard IR workflow."
    else:
        return "P4 - LOW", "badge-p4", "Minor incident. Informational or low-risk threat. Routine resolution."


# Sidebar
st.sidebar.image("https://img.icons8.com/fluency/96/siren.png", width=80)
st.sidebar.title("🚨 CyberIncident")
st.sidebar.caption("DFIR Triage & Incident Assistant")
st.sidebar.markdown("---")
st.sidebar.markdown("""
### Framework Modules:
- 🎯 **Incident Triage & Severity Matrix**
- 📖 **NIST SP 800-61 Playbooks**
- 🔬 **IOC & Evidence Logger**
- ⏱️ **Forensic Timeline Recorder**
- 📑 **Executive Post-Incident Report (PIR)**
""")
st.sidebar.markdown("---")
st.sidebar.info("💡 Follow the NIST lifecycle: Preparation -> Identification -> Containment -> Eradication -> Recovery -> Lessons Learned.")

# Main Header
st.markdown('<div class="cir-title">🚨 CyberIncident — Cyber Incident Response Assistant</div>', unsafe_allow_html=True)
st.markdown('<div class="cir-subtitle">Digital Forensics & Incident Response (DFIR) orchestration, playbooks, and automated triage reporting</div>', unsafe_allow_html=True)

tab_triage, tab_playbook, tab_evidence, tab_report = st.tabs([
    "🎯 Incident Triage & Scoping",
    "📖 Incident Playbooks",
    "🔬 IOC Evidence & Timeline",
    "📑 Post-Incident Report (PIR)"
])

# ----------------- TAB 1: TRIAGE ----------------- #
with tab_triage:
    st.markdown("### Incident Identification & Scoping")
    tcol1, tcol2 = st.columns(2)

    with tcol1:
        incident_id = st.text_input("Incident Reference Ticket:", value="INC-2026-8841")
        incident_title = st.text_input("Incident Title:", value="Active Ransomware Outbreak on File Share Cluster")
        attack_vector = st.selectbox(
            "Primary Attack Vector",
            ["Ransomware / Extortion", "Phishing / Business Email Compromise (BEC)", "DDoS Attack", "Unauthorized Access / Account Takeover", "Malware / C2 Beaconing", "Insider Threat / Data Exfiltration"]
        )
        lead_analyst = st.text_input("Incident Commander / Lead Analyst:", value="Alex Rivera, CISSP")

    with tcol2:
        affected_systems = st.number_input("Number of Impacted Endpoints / Servers:", min_value=1, value=14, step=1)
        data_impact = st.selectbox(
            "Data & Integrity Impact",
            ["Data Encrypted / Damaged", "Confidential Data Exfiltrated", "Internal Telemetry Only", "No Sensitive Data Impact"]
        )
        business_impact = st.selectbox(
            "Business Operational Disruption",
            ["Complete Operations Outage", "Significant Disruption", "Minor Inconvenience", "No Operational Impact"]
        )

    # Compute Severity
    sev_tier, sev_css, sev_desc = calculate_severity(attack_vector, affected_systems, data_impact, business_impact)

    st.markdown("---")
    st.markdown("### 🚦 Severity Assessment Result")
    sc1, sc2 = st.columns([1, 3])
    with sc1:
        st.markdown(f'<div class="{sev_css}" style="text-align: center; margin-top: 10px;">{sev_tier}</div>', unsafe_allow_html=True)
    with sc2:
        st.write(f"**Operational Scope:** {sev_desc}")
        st.write(f"**Classification:** {attack_vector} | Systems Impacted: **{affected_systems}** | Data Impact: **{data_impact}**")


# ----------------- TAB 2: PLAYBOOKS ----------------- #
with tab_playbook:
    st.markdown(f"### Structured Response Playbook: {attack_vector}")
    active_playbook = PLAYBOOKS.get(attack_vector, PLAYBOOKS["Ransomware / Extortion"])

    for phase, tasks in active_playbook.items():
        with st.expander(f"🔹 {phase} ({len(tasks)} Action Items)", expanded=True):
            for i, task in enumerate(tasks):
                st.checkbox(task, key=f"{attack_vector}_{phase}_{i}")


# ----------------- TAB 3: EVIDENCE & TIMELINE ----------------- #
with tab_evidence:
    st.markdown("### 🔬 Indicators of Compromise (IOC) Logger")
    e1, e2, e3 = st.columns([2, 4, 3])
    ioc_type = e1.selectbox("IOC Category", ["Malicious IP", "Domain Name", "SHA-256 Hash", "MD5 Hash", "Compromised Account", "Malicious URL"])
    ioc_val = e2.text_input("IOC Value (e.g., 203.0.113.5 or hash)", key="ioc_input")
    ioc_note = e3.text_input("Context / Source Note", key="ioc_note")

    if st.button("➕ Add IOC to Evidence Vault"):
        if ioc_val:
            st.session_state["iocs"].append({"type": ioc_type, "value": ioc_val.strip(), "notes": ioc_note.strip()})
            st.success(f"Added {ioc_type}: {ioc_val}")

    if st.session_state["iocs"]:
        st.dataframe(pd.DataFrame(st.session_state["iocs"]), use_container_width=True)

    st.markdown("---")
    st.markdown("### ⏱️ Incident Action Timeline")
    t1, t2, t3 = st.columns([2, 2, 4])
    t_time = t1.text_input("Timestamp", value=datetime.now().strftime("%Y-%m-%d %H:%M"))
    t_actor = t2.text_input("Operator / Role", value="Lead DFIR Analyst")
    t_act = t3.text_input("Action Executed / Observation")

    if st.button("➕ Append to Timeline"):
        if t_act:
            st.session_state["timeline"].append({"time": t_time, "actor": t_actor, "action": t_act})
            st.success("Timeline updated.")

    if st.session_state["timeline"]:
        st.dataframe(pd.DataFrame(st.session_state["timeline"]), use_container_width=True)


# ----------------- TAB 4: REPORT GENERATOR ----------------- #
with tab_report:
    st.markdown("### 📑 Executive Post-Incident Report (PIR) Generator")
    st.write("Synthesize an executive-ready Incident Summary Report for leadership, legal compliance, and technical audit.")

    pir_data = {
        "incident_id": incident_id,
        "title": incident_title,
        "commander": lead_analyst,
        "classification": attack_vector,
        "severity": sev_tier,
        "affected_systems_count": affected_systems,
        "data_impact": data_impact,
        "business_impact": business_impact,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "indicators_of_compromise": st.session_state["iocs"],
        "timeline": st.session_state["timeline"]
    }

    rcol1, rcol2 = st.columns(2)

    rcol1.download_button(
        "📥 Download JSON Incident File",
        data=json.dumps(pir_data, indent=4),
        file_name=f"{incident_id}_pir_report.json",
        mime="application/json"
    )

    pir_md = f"""# EXECUTIVE POST-INCIDENT REPORT (PIR)
**Incident ID:** {incident_id}  
**Date of Report:** {pir_data['generated_at']}  
**Incident Commander:** {lead_analyst}  
**Classification:** {attack_vector}  
**Severity Rating:** {sev_tier}  

---

## 1. Executive Summary
On {datetime.now().strftime('%Y-%m-%d')}, our Security Operations Center triaged an incident involving **{attack_vector}**, designated as **{incident_id}**. The incident resulted in operational disruption characterized as **{business_impact}**, affecting approximately **{affected_systems}** enterprise systems. The overall severity has been graded as **{sev_tier}**.

## 2. Impact Assessment
- **Affected Assets:** {affected_systems} Endpoints / Servers
- **Data Integrity Impact:** {data_impact}
- **Operational Impact:** {business_impact}

## 3. Indicators of Compromise (IOCs)
| Type | Value | Context / Notes |
|---|---|---|
"""
    for item in st.session_state["iocs"]:
        pir_md += f"| {item['type']} | `{item['value']}` | {item['notes']} |\n"

    pir_md += """
## 4. Incident Response Action Timeline
| Timestamp | Operator | Action Taken |
|---|---|---|
"""
    for entry in st.session_state["timeline"]:
        pir_md += f"| {entry['time']} | {entry['actor']} | {entry['action']} |\n"

    pir_md += """
## 5. Corrective Actions & Root Cause Remediation
1. **Endpoint Protection**: Ensure all production servers run updated EDR software with active behavioral isolation rules.
2. **Access Control**: Enforce mandatory Multi-Factor Authentication (MFA) across all remote access gateways and privileged accounts.
3. **Immutable Backups**: Validate that offline, air-gapped snapshots are tested and functional weekly.
4. **Post-Mortem Review**: Conduct a cross-functional lessons-learned session within 7 business days.

---
*Report generated automatically by CyberIncident Assistant.*
"""

    rcol2.download_button(
        "📥 Download Markdown PIR Report",
        data=pir_md,
        file_name=f"{incident_id}_pir_report.md",
        mime="text/markdown"
    )

    with st.expander("📄 Live Report Preview"):
        st.markdown(pir_md)
