"""
About page for TrustLens AI.
Displays project metadata, objectives, feature lists, and institutional context.
"""

import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="TrustLens AI - System Information",
    page_icon="ℹ️",
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
    
    /* Premium Info Card */
    .about-card {
        background-color: #ffffff; 
        padding: 24px; 
        border-radius: 16px; 
        border: 1px solid #f1f5f9; 
        box-shadow: 0 4px 12px rgba(15,23,42,0.02);
        margin-bottom: 1.2rem;
    }
    
    .about-card h3 {
        font-family: 'Outfit', sans-serif; 
        color: #0f172a; 
        margin-top: 0; 
        margin-bottom: 0.8rem;
        font-weight: 700;
        font-size: 1.3rem;
        border-bottom: 2px solid #f8fafc;
        padding-bottom: 0.4rem;
    }
    
    .about-card p, .about-card ul {
        font-size: 0.95rem; 
        color: #475569; 
        line-height: 1.65; 
        margin: 0;
    }
    
    .about-card ul {
        padding-left: 20px;
    }
    
    .about-card li {
        margin-bottom: 0.5rem;
    }
    
    .about-card li:last-child {
        margin-bottom: 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<h1 class='page-title'>ℹ️ System Information</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='page-desc'>Review the operational parameters, objectives, and institutional metadata of the TrustLens AI platform.</p>",
    unsafe_allow_html=True,
)

# Sidebar branding card
st.sidebar.markdown(
    """
    <div style='background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); padding: 20px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; text-align: center;'>
        <div style='font-size: 2.2rem; margin-bottom: 8px;'>ℹ️</div>
        <h3 style='font-family: Outfit; font-weight: 800; color: #0f172a; margin: 0; font-size: 1.4rem;'>System Info</h3>
        <span style='color: #64748b; font-size: 0.85rem;'>Release Specifications</span>
    </div>
    """,
    unsafe_allow_html=True,
)

col1, col2 = st.columns(2, gap="large")

with col1:
    st.markdown(
        """
        <div class="about-card">
            <h3>Project Scope</h3>
            <p style="font-size: 1.1rem; font-weight: bold; color: #6366f1;">TrustLens AI (Enterprise Security Edition)</p>
        </div>
        
        <div class="about-card">
            <h3>Project Objective</h3>
            <p>
                To build a secure, pre-execution static threat analysis and trust profiling platform for compiled binaries and documents. 
                By extracting structural features in memory without executing code, the system calculates transparent safety scores 
                and aligns anomalies with the MITRE ATT&CK taxonomy, providing actionable threat context.
            </p>
        </div>
        
        <div class="about-card">
            <h3>Key Capabilities</h3>
            <ul>
                <li><b>Zero-Execution Static Scanning</b>: Assesses compiled binary header structures safely without running code.</li>
                <li><b>Transparent Safety Profiling</b>: Computes Trust Scores and Risk Levels combined with clear warnings.</li>
                <li><b>MITRE ATT&CK Mapping</b>: Automatically maps header anomalies to standardized adversary tactics.</li>
                <li><b>Automated Security Reporting</b>: Compiles and downloads printable PDF security audit reports.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        """
        <div class="about-card">
            <h3>Technology Stack</h3>
            <p>
                • <b>Core Logic</b>: Python 3.14<br>
                • <b>Parsing Engine</b>: PEFile & pypdf Library Plugins<br>
                • <b>Classification Backend</b>: Scikit-Learn Ensemble RandomForest<br>
                • <b>Interface</b>: Streamlit Web UI<br>
                • <b>Report Engine</b>: ReportLab PDF Canvas
            </p>
        </div>
        
        <div class="about-card">
            <h3>Release Version</h3>
            <p style="font-size: 1.1rem; font-weight: bold; color: #6366f1;">v1.0.0 Stable (Standard Academic Release)</p>
        </div>
        
        <div class="about-card">
            <h3>Development Context</h3>
            <table style="width: 100%; font-size: 0.95rem; color: #475569; border-collapse: collapse;">
                <tr>
                    <td style="padding: 6px 0; font-weight: bold; width: 35%;">Developed By:</td>
                    <td style="padding: 6px 0;">Computer Science & Engineering (Data Science) Candidates</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; font-weight: bold;">Project Guide:</td>
                    <td style="padding: 6px 0;">Department of CSE (Data Science) Faculty</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; font-weight: bold;">Institution:</td>
                    <td style="padding: 6px 0;">Annamacharya Institute of Technology and Sciences (Autonomous), Rajampet</td>
                </tr>
            </table>
        </div>
        """,
        unsafe_allow_html=True,
    )
