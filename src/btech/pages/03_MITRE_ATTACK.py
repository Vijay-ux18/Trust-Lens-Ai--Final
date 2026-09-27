"""
MITRE ATT&CK Analysis page for TrustLens AI.
Maps detected binary behaviors to attacker tactics and techniques.
"""

import pandas as pd
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="TrustLens AI - MITRE ATT&CK Analysis",
    page_icon="🎯",
    layout="wide",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Inter:wght@400;500;600&display=swap');
    
    .page-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 800;
        font-size: 2.2rem;
        color: #f8fafc !important;
        margin-bottom: 0.5rem;
    }
    
    .page-desc {
        color: #94a3b8 !important;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }
    
    /* MITRE Card Components */
    .mitre-card {
        background-color: #ffffff; 
        padding: 24px; 
        border-radius: 16px; 
        border: 1px solid #f1f5f9; 
        box-shadow: 0 4px 12px rgba(15,23,42,0.02);
        margin-bottom: 1.2rem; 
        border-left: 6px solid #6366f1;
        transition: transform 0.2s ease;
    }
    
    .mitre-card:hover {
        transform: translateX(4px);
        border-color: #e2e8f0;
    }
    
    .tactic-badge {
        font-family: 'Inter', sans-serif;
        font-weight: 600; 
        font-size: 0.75rem; 
        text-transform: uppercase; 
        color: #6366f1;
        background-color: #eef2ff;
        padding: 4px 12px;
        border-radius: 12px;
        display: inline-block;
        letter-spacing: 0.05em;
    }
    
    .technique-id {
        float: right;
        font-family: monospace;
        font-weight: bold;
        color: #ef4444;
        background-color: #fef2f2;
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.85rem;
    }
    
    .mitre-title {
        font-family: 'Outfit', sans-serif;
        font-size: 1.25rem; 
        font-weight: 700; 
        color: #0f172a; 
        margin-top: 0.6rem;
    }
    
    .mitre-desc {
        font-size: 0.95rem; 
        color: #475569; 
        margin-top: 0.6rem; 
        line-height: 1.6;
    }
    
    /* Technical Metadata Tables */
    .tech-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.9rem;
        color: #334155;
    }
    
    .tech-table th {
        background-color: #f8fafc;
        padding: 10px;
        font-weight: 600;
        text-align: left;
        border-bottom: 2px solid #e2e8f0;
    }
    
    .tech-table td {
        padding: 10px;
        border-bottom: 1px solid #f1f5f9;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<h1 class='page-title'>🎯 MITRE ATT&CK Analysis</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='page-desc'>Maps structural anomalies and flagged metrics detected in code layers directly to adversary tactics and techniques.</p>",
    unsafe_allow_html=True,
)

# Sidebar branding card
st.sidebar.markdown(
    """
    <div style='background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); padding: 20px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; text-align: center;'>
        <div style='font-size: 2.2rem; margin-bottom: 8px;'>🎯</div>
        <h3 style='font-family: Outfit; font-weight: 800; color: #0f172a; margin: 0; font-size: 1.4rem;'>MITRE Maps</h3>
        <span style='color: #64748b; font-size: 0.85rem;'>MITRE ATT&CK®-based heuristic mapping</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# Resolution helper function mapping structural alerts to MITRE tactics
def map_anomaly_to_mitre(anomaly: str) -> dict:
    anomaly_lower = anomaly.lower()
    if "entropy" in anomaly_lower or "obfuscation" in anomaly_lower:
        return {
            "Detected Behaviour": "Software Obfuscation via Packing",
            "ATT&CK Tactic": "Defense Evasion",
            "Simple Human Explanation": "The file contains highly random or encrypted sections, which are commonly used by threat actors to conceal malicious payloads from static signature-based detection.",
            "Potential ATT&CK association": "T1027.002",
            "Mapping Rules": "obfuscation_score > 3 or entropy > 7.2",
            "Detection Logic": "Scans file sections and data streams for high byte randomness or hex/character escape counts.",
            "Technical Notes": "Commonly associated with UPX packing, script encoding modules, or custom cryptors.",
        }
    elif "import" in anomaly_lower or "dynamic" in anomaly_lower:
        return {
            "Detected Behaviour": "Hidden Library Dependency Loading",
            "ATT&CK Tactic": "Defense Evasion",
            "Simple Human Explanation": "The file imports minimal external functions directly, suggesting it resolves operating system routines dynamically at runtime to hide its full scope.",
            "Potential ATT&CK association": "T1027",
            "Mapping Rules": "ImportsNb < 10",
            "Detection Logic": "Counts total functions resolved in the Import Address Table (IAT).",
            "Technical Notes": "Calls API routines dynamically via LoadLibrary or GetProcAddress signatures.",
        }
    elif (
        "aslr" in anomaly_lower
        or "dep" in anomaly_lower
        or "mitigation" in anomaly_lower
        or "memory" in anomaly_lower
    ):
        return {
            "Detected Behaviour": "Vulnerable Security Configuration",
            "ATT&CK Tactic": "Execution / Privilege Escalation",
            "Simple Human Explanation": "The binary lacks essential compile-time safety guards (such as DEP/ASLR), exposing stack and heap memory ranges to privilege takeover or hijack methods.",
            "Potential ATT&CK association": "N/A (Exploitation Pre-condition)",
            "Mapping Rules": "DEP / ASLR flags set to 0",
            "Detection Logic": "Audits the DllCharacteristics bitmask field in the PE optional header.",
            "Technical Notes": "Disabled memory randomization permits ROP stack exploitation.",
        }
    elif "checksum" in anomaly_lower or "header" in anomaly_lower:
        return {
            "Detected Behaviour": "Modified Header Configuration",
            "ATT&CK Tactic": "Defense Evasion",
            "Simple Human Explanation": "The file's validation checksum is missing or incorrect, suggesting the compiled bytes have been altered or patched post-linking.",
            "Potential ATT&CK association": "T1553",
            "Mapping Rules": "CheckSum = 0",
            "Detection Logic": "Checks the CheckSum header field in the PE optional header.",
            "Technical Notes": "Indicates manual byte modifications or file-appending virus contamination.",
        }
    elif (
        "image size" in anomaly_lower
        or "virtual size" in anomaly_lower
        or "memory footprint" in anomaly_lower
    ):
        return {
            "Detected Behaviour": "Abnormal Memory Footprint Allocation",
            "ATT&CK Tactic": "Defense Evasion / Execution",
            "Simple Human Explanation": "The program reserves significantly more memory range than its disk size, a behavior typical of runtime injection, unpacking, or dynamic buffer allocations.",
            "Potential ATT&CK association": "T1055",
            "Mapping Rules": "Virtual Size >> Disk Size",
            "Detection Logic": "Compares virtual size in memory to raw size on disk across sections.",
            "Technical Notes": "Creates memory padding to contain unpacking shells or custom shellcodes.",
        }
    elif "masquerading" in anomaly_lower or "spoofing" in anomaly_lower:
        return {
            "Detected Behaviour": "Masquerading & Double Extensions",
            "ATT&CK Tactic": "Defense Evasion",
            "Simple Human Explanation": "The file extension is spoofed to mask its execution capability (e.g. document extensions hiding executable magic signatures).",
            "Potential ATT&CK association": "T1036.008",
            "Mapping Rules": "has_masquerading = 1.0",
            "Detection Logic": "Correlates filename extensions with underlying magic file signatures.",
            "Technical Notes": "Used in phishing files targeting email gateways.",
        }
    elif "macro" in anomaly_lower or "script" in anomaly_lower:
        return {
            "Detected Behaviour": "VBA Macro / Code Execution",
            "ATT&CK Tactic": "Execution",
            "Simple Human Explanation": "The file contains macro code modules designed to trigger system commands or download secondary binaries when opened.",
            "Potential ATT&CK association": "Potential T1204.002 (Requires Execution)",
            "Mapping Rules": "has_macros_or_scripts = 1.0",
            "Detection Logic": "Inspects document ZIP rels streams for vbaProject.bin objects.",
            "Technical Notes": "Fires PowerShell download strings upon document activation.",
        }
    return None

# Check for last scan anomalies in session state
last_scan_name = st.session_state.get("last_scan_name", None)
last_scan_anomalies = st.session_state.get("last_scan_anomalies", [])

st.markdown("<h3 style='font-family: Outfit; font-weight: 700; font-size: 1.4rem; color: #f8fafc !important; margin-bottom: 1.2rem;'>🔍 Active Scan Mappings</h3>", unsafe_allow_html=True)

if last_scan_name:
    st.write(f"Correlating detected anomalies for file: **{last_scan_name}**")

    # Filter and map anomalies
    resolved_mappings = []
    for anomaly in last_scan_anomalies:
        mapping = map_anomaly_to_mitre(anomaly)
        if mapping and mapping not in resolved_mappings:
            resolved_mappings.append(mapping)

    if len(resolved_mappings) == 0:
        # Success state card
        st.markdown(
            """
            <div style='background-color: #ecfdf5; border-left: 6px solid #10b981; padding: 20px; border-radius: 12px; font-size: 0.95rem; color: #065f46;'>
                ✅ <strong>Zero Threat Tactics Identified</strong>: The analyzed file matches all standard security baselines. No MITRE ATT&CK tactics have been attributed to its features.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        # Render MITRE Cards
        for item in resolved_mappings:
            st.markdown(
                f"""
                <div class="mitre-card">
                    <span class="technique-id">{item['MITRE Technique IDs']}</span>
                    <span class="tactic-badge">{item['ATT&CK Tactic']}</span>
                    <div class="mitre-title">{item['Detected Behaviour']}</div>
                    <div class="mitre-desc">{item['Simple Human Explanation']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # Expandable Advanced Technical Details Table
        with st.expander("🔬 View Mapping Logic & Technical Specifications"):
            tech_html = """
            <table class="tech-table">
                <thead>
                    <tr>
                        <th>Tactic & ID</th>
                        <th>Mapping Trigger</th>
                        <th>Detection Logic</th>
                        <th>Technical Specifications</th>
                    </tr>
                </thead>
                <tbody>
            """
            for item in resolved_mappings:
                tech_html += f"""
                <tr>
                    <td><strong>{item['ATT&CK Tactic']}</strong><br><span style="color:#ef4444; font-family:monospace;">{item['MITRE Technique IDs']}</span></td>
                    <td><span style="background-color:#f1f5f9; padding:2px 6px; border-radius:4px; font-family:monospace; font-size:0.85rem;">{item['Mapping Rules']}</span></td>
                    <td>{item['Detection Logic']}</td>
                    <td><span style="color:#475569; font-size:0.85rem;">{item['Technical Notes']}</span></td>
                </tr>
                """
            tech_html += "</tbody></table>"
            st.markdown(tech_html, unsafe_allow_html=True)

else:
    # Empty State card
    st.markdown(
        """
        <div style='text-align: center; padding: 4rem 2rem; background-color: #f8fafc; border-radius: 16px; border: 2px dashed #cbd5e1; margin-top: 1rem;'>
            <div style='font-size: 3rem; margin-bottom: 1rem;'>🎯</div>
            <h3 style='font-family: Outfit; font-weight: 600; color: #475569; margin: 0;'>No Active Scan Loaded</h3>
            <p style='color: #64748b; margin-top: 0.5rem;'>Run a file scanner check on the <strong>Upload & Predict</strong> page to correlate its structural findings with adversary techniques.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
