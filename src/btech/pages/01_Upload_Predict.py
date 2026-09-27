"""
Upload & Predict page for TrustLens AI.
Allows users to upload binary documents or archives, parses features,
runs predictions on the multi-format pipeline, and generates PDF reports.
"""

import html
import logging
import os
import sys
import traceback
import plotly.graph_objects as go
import streamlit as st

# Configure logger
logger = logging.getLogger("btech.scanner_ui")

# Add src to sys.path so btech module can be imported without installation
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from btech.predict import TrustLensPredictor
from btech.report import generate_pdf_report
from btech.hash_reputation import lookup_virustotal_hash

# Configure page settings
st.set_page_config(
    page_title="TrustLens AI - Upload & Predict",
    page_icon="📤",
    layout="wide",
)

# Initialize global scan history in session state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# Custom CSS for Upload & Predict Page
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600&display=swap');
    
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
    
    .tl-section-heading { font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 1.4rem; color: #f8fafc !important; margin: 0 0 1.0rem 0; }

    /* Styled Metric Cards */
    .metric-card {
        padding: 24px;
        border-radius: 16px;
        box-shadow: 0 4px 12px rgba(15,23,42,0.03);
        border: 1px solid #f1f5f9;
        border-left: 6px solid #cbd5e1;
        background-color: #ffffff;
        margin-bottom: 1.2rem;
    }
    
    .safe-risk {
        border-left-color: #10b981;
        background-color: #f0fdf4;
    }
    
    .low-risk {
        border-left-color: #3b82f6;
        background-color: #eff6ff;
    }
    
    .medium-risk {
        border-left-color: #f59e0b;
        background-color: #fffbeb;
    }
    
    .high-risk {
        border-left-color: #ef4444;
        background-color: #fef2f2;
    }
    
    .critical-risk {
        border-left-color: #7f1d1d;
        background-color: #fff1f2;
    }
    
    .risk-title {
        font-family: 'Outfit', sans-serif;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        color: #64748b;
        letter-spacing: 0.05em;
    }
    
    .risk-value {
        font-family: 'Outfit', sans-serif;
        font-size: 2rem;
        font-weight: 800;
        margin-top: 0.25rem;
    }
    
    .risk-desc {
        font-size: 0.95rem;
        margin-top: 0.6rem;
        color: #475569;
        line-height: 1.6;
    }
    
    /* Info Card Grid */
    .info-table-card {
        background-color: #f8fafc; 
        padding: 24px; 
        border-radius: 16px; 
        border: 1px solid #e2e8f0; 
        margin-bottom: 1.5rem;
    }
    
    .info-table {
        width: 100%; 
        font-size: 0.95rem; 
        color: #334155; 
        border-collapse: collapse;
    }
    
    .info-table td {
        padding: 10px 0;
        border-bottom: 1px solid #e2e8f0;
    }
    
    .info-table tr:last-child td {
        border-bottom: none;
    }
    
    .threat-card { background: rgba(15,23,42,0.78); border: 1px solid #334155; border-radius: 14px; padding: 16px 18px; margin-bottom: 1.4rem; }
    .threat-row { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 7px 0; color: #e2e8f0; }
    .threat-label { color: #94a3b8; font-size: 0.88rem; font-weight: 600; }
    .threat-card code { color: #e2e8f0; background: #1e293b; padding: 4px 8px; border-radius: 6px; }
    .threat-note { color: #94a3b8; font-size: 0.78rem; margin-top: 8px; line-height: 1.5; }
    .ti-ok { color: #34d399; font-weight: 600; }
    .ti-alert { color: #fb7185; font-weight: 600; }
    .ti-muted { color: #cbd5e1; font-weight: 600; }

    /* Diagnostic Terminal Report */
    .terminal-report {
        background-color: #0f172a; 
        padding: 25px; 
        border-radius: 16px; 
        border: 1px solid #1e293b; 
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; 
        font-size: 0.95rem; 
        color: #f1f5f9; 
        line-height: 1.7; 
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 25px rgba(15,23,42,0.15);
    }
    
    .terminal-success-badge {
        color: #10b981;
        font-weight: bold;
    }
    
    .terminal-alert-badge {
        color: #f43f5e;
        font-weight: bold;
    }
    
    .terminal-warning-badge {
        color: #fbbf24;
        font-weight: bold;
    }
    
    /* Recommendations Section */
    .rec-container {
        padding: 20px;
        background-color: #f8fafc;
        border-radius: 12px;
        border: 1px solid #cbd5e1;
        margin-bottom: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<h1 class='page-title'>📤 Upload & Analyze Binary</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='page-desc'>Submit documents, scripts, executables, or compressed packages for zero-execution structural assessment and risk scores.</p>",
    unsafe_allow_html=True,
)

# Sidebar branding card
st.sidebar.markdown(
    """
    <div style='background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); padding: 20px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; text-align: center;'>
        <div style='font-size: 2.2rem; margin-bottom: 8px;'>📤</div>
        <h3 style='font-family: Outfit; font-weight: 800; color: #0f172a; margin: 0; font-size: 1.4rem;'>Upload Terminal</h3>
        <span style='color: #64748b; font-size: 0.85rem;'>TrustLens Engine Active</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# Initialize predictor
predictor = TrustLensPredictor()
predictor.load_assets()

# File Uploader with clean framing
uploaded_file = st.file_uploader(
    "Drag and drop files here or browse local folders",
    type=[
        "exe", "dll", "sys", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm",
        "txt", "csv", "zip", "rar", "msi", "bat", "ps1", "js", "vbs", "apk",
        "jpg", "png",
    ],
    label_visibility="collapsed"
)

if uploaded_file is not None:
    # Sanitize file name for path traversal
    file_name = os.path.basename(uploaded_file.name)
    safe_file_name = html.escape(file_name)
    file_bytes = uploaded_file.read()
    if len(file_bytes) > 50 * 1024 * 1024:
        st.error("File exceeds maximum allowed size of 50 MB.")
        st.stop()
    file_size_kb = len(file_bytes) / 1024

    st.markdown("<br>", unsafe_allow_html=True)

    with st.spinner("Decoding file headers and calculating byte randomness..."):
        try:
            # Execute prediction
            result = predictor.predict_file(file_bytes, filename=file_name)

            # Optional hash-only external reputation: file bytes are never uploaded.
            reputation = lookup_virustotal_hash(file_bytes)

            trust_score = result["trust_score"]
            risk_category = result["risk_category"]
            rule_explanations = result["rule_explanations"]
            recommendations = result["recommendations"]
            short_explanation = result["short_explanation"]
            features = result["features"]
            is_mock = result["is_mock"]
            explanation_data = result["explanation_data"]

            # Map parameter values for risk rendering
            if risk_category == "Safe":
                card_class = "safe-risk"
                risk_color = "#10b981"
                terminal_badge = "<span class='terminal-success-badge'>[SAFE]</span>"
                risk_desc = "The file complies fully with safety baselines and shows zero indicators of compromise."
            elif risk_category == "Low":
                card_class = "low-risk"
                risk_color = "#3b82f6"
                terminal_badge = "<span class='terminal-success-badge'>[LOW RISK]</span>"
                risk_desc = "Legitimate signature matches. File features are safe with expected structural flags."
            elif risk_category == "Medium":
                card_class = "medium-risk"
                risk_color = "#f59e0b"
                terminal_badge = "<span class='terminal-warning-badge'>[WARNING]</span>"
                risk_desc = "Minor warnings detected (e.g. hyperlinks or embedded objects). Proceed with caution."
            elif risk_category == "High":
                card_class = "high-risk"
                risk_color = "#ef4444"
                terminal_badge = "<span class='terminal-alert-badge'>[ALERT]</span>"
                risk_desc = "Obfuscation keywords, nested executable files, or active VBA scripts identified."
            else:  # Critical
                card_class = "critical-risk"
                risk_color = "#7f1d1d"
                terminal_badge = "<span class='terminal-alert-badge'>[CRITICAL THREAT]</span>"
                risk_desc = "Active evasion, spoofed document extensions, or highly malicious code structures found."

            # Simple hash/reputation summary
            reputation_status = reputation.get("status", "not_checked")
            if reputation_status == "found":
                rep_text = f"Known reputation match: {reputation.get("detection_count", 0)}/{reputation.get("total_engines", 0)} engines"
                rep_class = "ti-alert"
            elif reputation_status == "not_found":
                rep_text = "No match found in the configured reputation provider"
                rep_class = "ti-ok"
            else:
                rep_text = "External reputation not checked"
                rep_class = "ti-muted"

            st.markdown("<div class='tl-section-heading'>🔎 Threat Intelligence</div>", unsafe_allow_html=True)
            st.markdown(
                f"""
                <div class='threat-card'>
                    <div class='threat-row'><span class='threat-label'>SHA-256</span><code>{html.escape(reputation.get('sha256','')[:24])}…</code></div>
                    <div class='threat-row'><span class='threat-label'>External reputation</span><span class='{rep_class}'>{html.escape(rep_text)}</span></div>
                    <div class='threat-note'>Hash-only lookup. The uploaded file is not sent to the reputation provider. External reputation is supporting evidence, not the ML prediction.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Save scan details to history
            history_exists = any(h["filename"] == file_name for h in st.session_state.scan_history)
            if not history_exists:
                st.session_state.scan_history.append(
                    {
                        "filename": file_name,
                        "file_type": features.get("file_format", "Unknown Format"),
                        "file_size": f"{file_size_kb:.1f} KB",
                        "trust_score": trust_score,
                        "risk_level": f"{risk_category} Risk",
                        "risk_category": risk_category,
                        "anomalies": rule_explanations,
                    }
                )
                st.session_state.last_scan_name = file_name
                st.session_state.last_scan_anomalies = rule_explanations

            # Render Layout Columns
            col_left, col_right = st.columns([1, 1.5], gap="large")

            with col_left:
                # 1. Trust Score Plotly Gauge (with matching clean aesthetics)
                fig_gauge = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=trust_score,
                        domain={"x": [0, 1], "y": [0, 1]},
                        number={"suffix": "%", "font": {"size": 28, "family": "Outfit", "color": "#d7dae2"}},
                        gauge={
                            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94a3b8"},
                            "bar": {"color": "#6366f1", "thickness": 0.25},
                            "bgcolor": "#f8fafc",
                            "borderwidth": 1,
                            "bordercolor": "#e2e8f0",
                            "steps": [
                                {"range": [0, 20], "color": "#fee2e2"},
                                {"range": [20, 50], "color": "#fee2e2"},
                                {"range": [50, 80], "color": "#fef3c7"},
                                {"range": [80, 95], "color": "#eff6ff"},
                                {"range": [95, 100], "color": "#ecfdf5"},
                            ],
                        },
                    )
                )
                fig_gauge.update_layout(
                    height=180,
                    margin=dict(t=25, b=0, l=15, r=15),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                )
                st.markdown(
                    """
                    <div style="text-align:center; font-family: Outfit; font-weight:700; font-size:0.95rem; color:#64748b; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:-10px;">
                        File Trust Index
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

                # 2. Risk Level Card
                st.markdown(
                    f"""
                    <div class="metric-card {card_class}">
                        <div class="risk-title">Security Risk Level</div>
                        <div class="risk-value" style="color: {risk_color};">{risk_category} Risk</div>
                        <div class="risk-desc">{risk_desc}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with col_right:
                # 3. File Info Grid
                st.markdown(
                    f"""
                    <div class="info-table-card">
                        <h4 style="margin-top: 0; font-family: Outfit; color: #0f172a; font-weight: 700; font-size: 1.2rem;">File Overview</h4>
                        <table class="info-table">
                            <tr>
                                <td style="font-weight: 600; width: 30%;">File Name</td>
                                <td>{safe_file_name}</td>
                            </tr>
                            <tr>
                                <td style="font-weight: 600;">Detected Class</td>
                                <td>{features.get("file_format", "Document File")}</td>
                            </tr>
                            <tr>
                                <td style="font-weight: 600;">File Size</td>
                                <td>{file_size_kb:.2f} KB</td>
                            </tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # 4. Diagnostic Log Block
                st.markdown("<div class='tl-section-heading'>📝 Security Diagnostic Report</div>", unsafe_allow_html=True)
                
                reasons_str = "\n".join(f"✓ {r}" for r in result["reasons"])
                if not reasons_str:
                    reasons_str = "✓ No structural anomalies identified."

                report_block = f"""
                <div class="terminal-report">
                    SYSTEM STATUS      : ACTIVE<br>
                    RISK ATTRIBUTION   : {terminal_badge}<br>
                    TRUST SCORE INDEX  : {int(trust_score)} / 100<br>
                    MODEL CONFIDENCE   : {result['confidence']}%<br><br>
                    <strong>[Triggered Rules & Indicators]</strong><br>
                    {reasons_str.replace('\n', '<br>')}<br><br>
                    <strong>[Analyst Recommendation]</strong><br>
                    {result['recommendation']}
                </div>
                """
                st.markdown(report_block, unsafe_allow_html=True)

                # 5. PDF Security Certificate Generation Trigger
                try:
                    pdf_bytes = generate_pdf_report(
                        file_name,
                        features,
                        {
                            "trust_score": trust_score,
                            "risk_level": f"{risk_category} Risk",
                            "prediction": result["prediction"],
                        },
                        explanation_data,
                    )

                    st.download_button(
                        label="📥 Download PDF Security Report",
                        data=pdf_bytes,
                        file_name=f"TrustLens_Report_{file_name.replace('.', '_')}.pdf",
                        mime="application/pdf",
                    )
                except Exception as pdf_err:
                    logger.exception("PDF report compilation failed.")
                    st.error("Analysis complete, but PDF report generation failed due to an internal error.")

        except Exception as e:
            logger.exception("File scan analysis pipeline failed.")
            import traceback
            traceback.print_exc()
            st.error(f"Unable to analyze the uploaded file. An internal error occurred. {e}")

else:
    # Empty Upload state
    st.markdown(
        """
        <div style='text-align: center; padding: 4rem 2rem; background-color: #f8fafc; border-radius: 16px; border: 2px dashed #cbd5e1; margin-top: 1rem;'>
            <div style='font-size: 3rem; margin-bottom: 1rem;'>📤</div>
            <h3 style='font-family: Outfit; font-weight: 600; color: #475569; margin: 0;'>Awaiting Scan File Upload</h3>
            <p style='color: #64748b; margin-top: 0.5rem;'>Drop a binary or document package in the upload area above to start pre-execution safety scanning.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
