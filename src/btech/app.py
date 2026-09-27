"""
TrustLens AI Web Application.
Main landing page and portal.
"""

import os
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="TrustLens AI - Pre-Execution Binary Security Profiler",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize global scan history in session state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# Custom premium CSS styling injection
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;500;600;700;800&display=swap');
    
    /* Global Base Reset and Font Styling */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        color: #1e293b;
    }
    
    /* Premium Header Hero */
    .hero-container {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #3b4252 100%);
        padding: 3rem 2.5rem;
        border-radius: 24px;
        color: white;
        margin-bottom: 2.5rem;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.15);
        position: relative;
        overflow: hidden;
    }
    
    .hero-container::after {
        content: '';
        position: absolute;
        top: -50%;
        right: -30%;
        width: 300px;
        height: 300px;
        background: radial-gradient(circle, rgba(99, 102, 241, 0.2) 0%, rgba(99, 102, 241, 0) 70%);
        border-radius: 50%;
    }
    
    .main-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 800;
        font-size: 3rem;
        color: #ffffff;
        margin: 0;
        letter-spacing: -0.03em;
        line-height: 1.1;
    }
    
    .subtitle {
        font-size: 1.15rem;
        color: #94a3b8;
        margin-top: 0.5rem;
        margin-bottom: 0;
        font-weight: 400;
    }
    
    /* Section Headings */
    .section-header {
        font-family: 'Outfit', sans-serif;
        font-weight: 700;
        font-size: 1.6rem;
        color: #0f172a;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid #f1f5f9;
        padding-bottom: 0.5rem;
    }
    
    /* Feature Card Styles with Micro-Animations */
    .feature-card {
        background: #ffffff;
        border-radius: 16px;
        padding: 24px;
        border: 1px solid #f1f5f9;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.03);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        height: 100%;
        display: flex;
        flex-direction: column;
    }
    
    .feature-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 24px rgba(15, 23, 42, 0.08);
        border-color: #e2e8f0;
    }
    
    .feature-icon {
        font-size: 2.2rem;
        margin-bottom: 1rem;
        background: #f8fafc;
        width: 60px;
        height: 60px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 12px;
        border: 1px solid #f1f5f9;
    }
    
    .feature-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 600;
        font-size: 1.25rem;
        color: #0f172a;
        margin-bottom: 0.75rem;
    }
    
    .feature-desc {
        color: #475569;
        font-size: 0.95rem;
        line-height: 1.6;
    }
    
    /* Specs Sidebar Card */
    .specs-card {
        background: linear-gradient(145deg, #1e293b 0%, #0f172a 100%);
        border-radius: 16px;
        padding: 24px;
        color: #f8fafc;
        box-shadow: 0 10px 20px rgba(15, 23, 42, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    .specs-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 700;
        font-size: 1.3rem;
        color: #ffffff;
        margin-top: 0;
        margin-bottom: 1.2rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .spec-item {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        font-size: 0.95rem;
    }
    
    .spec-item:last-child {
        border-bottom: none;
    }
    
    .spec-label {
        color: #94a3b8;
    }
    
    .spec-val {
        font-weight: 500;
        color: #f8fafc;
    }
    
    /* Footer Styling */
    .footer-container {
        text-align: center;
        color: #64748b;
        font-size: 0.85rem;
        margin-top: 4rem;
        padding: 2rem 0;
        border-top: 1px solid #f1f5f9;
        font-family: 'Inter', sans-serif;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar navigation branding card
st.sidebar.markdown(
    """
    <div style='background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); padding: 20px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; text-align: center;'>
        <div style='font-size: 2.2rem; margin-bottom: 8px;'>🔍</div>
        <h3 style='font-family: Outfit; font-weight: 800; color: #0f172a; margin: 0; font-size: 1.4rem;'>TrustLens AI</h3>
        <span style='background-color: #e2e8f0; color: #334155; font-size: 0.75rem; font-weight: 600; padding: 3px 10px; border-radius: 12px; display: inline-block; margin-top: 8px;'>v1.0.0 Stable</span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.markdown(
    """
    <div style='padding: 10px 15px; background-color: #f8fafc; border-radius: 10px; border-left: 4px solid #6366f1; font-size: 0.9rem; color: #475569;'>
        Select a scanner page above to begin static inspections or view active session statistics.
    </div>
    """,
    unsafe_allow_html=True,
)

# Hero Header section
st.markdown(
    """
    <div class="hero-container">
        <h1 class="main-title">TrustLens AI</h1>
        <p class="subtitle">Explainable Machine Learning & Modular Plugin Architecture for Pre-Execution File Safety Profiling</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Portal Layout Grid
col_content, col_sidebar = st.columns([2, 1])

with col_content:
    st.markdown("<h2 class='section-header'>🛡️ Pre-Execution File Protection</h2>", unsafe_allow_html=True)
    st.markdown(
        """
        Conventional security gateways rely heavily on signature matching or execution-based sandboxes. Signature database matches fail against polymorphic variants, while dynamic execution sandboxes suffer from evasion traps and long execution delays.
        
        **TrustLens AI** implements a zero-execution paradigm, inspecting files statically and making safety predictions before any instruction loads:
        - **Modular Analyzer Plugins**: Evaluates formats (PDF, DOCX, ZIP, scripts, PE, images) through sandboxed, dedicated parsing components.
        - **Unified 10-D Feature Vectors**: Translates structural metadata into common dimensions like Shannon entropy, execution capabilities, and obfuscation scores.
        - **Intelligent Dual Models**: Runs Random Forest classification pipelines to output calibrated risk indexes.
        - **Adversary Tactics Attribution**: Correlates file anomalies to specific MITRE ATT&CK T-codes.
        """
    )
    
    st.markdown("<h2 class='section-header'>🧭 Navigation Guide</h2>", unsafe_allow_html=True)
    st.markdown(
        """
        - **📤 Upload & Predict**: Select this page to drag-and-drop binaries, documents, archives, or scripts for risk scoring, dynamic checklists, and ReportLab PDF security report exports.
        - **📊 Security Operations Dashboard**: Review cumulative session logs, classification metrics, and charts.
        - **🎯 MITRE ATT&CK Mapping**: Cross-reference structural indicators to standard adversary tactics.
        - **ℹ️ Security Glossary**: Read descriptions of security controls like ASLR, DEP, and section headers.
        """
    )

with col_sidebar:
    st.markdown(
        """
        <div class="specs-card">
            <div class="specs-title">⚙️ Deployment Specs</div>
            <div class="spec-item">
                <span class="spec-label">Platform Core</span>
                <span class="spec-val">Python 3.14 + Streamlit</span>
            </div>
            <div class="spec-item">
                <span class="spec-label">Predictive Engine</span>
                <span class="spec-val">Random Forest Classifiers</span>
            </div>
            <div class="spec-item">
                <span class="spec-label">Plugin Dispatcher</span>
                <span class="spec-val">Dynamic BaseAnalyzer</span>
            </div>
            <div class="spec-item">
                <span class="spec-label">Explanations</span>
                <span class="spec-val">Local feature attribution</span>
            </div>
            <div class="spec-item">
                <span class="spec-label">Document Mapping</span>
                <span class="spec-val">MITRE ATT&CK (v14)</span>
            </div>
            <div class="spec-item">
                <span class="spec-label">Status</span>
                <span class="spec-val" style="color: #10b981; font-weight: bold;">● Active Protection</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

# Grid Layout for Features
col_f1, col_f2, col_f3 = st.columns(3)

with col_f1:
    st.markdown(
        """
        <div class="feature-card">
            <div class="feature-icon">🛡️</div>
            <div class="feature-title">Zero-Execution Analysis</div>
            <div class="feature-desc">Analyzes structures statically in memory without launching file processes, avoiding endpoint contamination or VM-aware evasion traps.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_f2:
    st.markdown(
        """
        <div class="feature-card">
            <div class="feature-icon">🔍</div>
            <div class="feature-title">Explainable Security Alerts</div>
            <div class="feature-desc">Replaces black-box scores with concrete attributions: missing compiler protections, obfuscated code ranges, and macro embeds.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_f3:
    st.markdown(
        """
        <div class="feature-card">
            <div class="feature-icon">📋</div>
            <div class="feature-title">Printable Reports</div>
            <div class="feature-desc">Compiles instant, production-ready PDF reports containing feature dimensions, compliance lists, and recommended mitigations.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Footer Details
st.markdown(
    """
    <div class="footer-container">
        TrustLens AI Portal • Developed at Annamacharya Institute of Technology and Sciences (Autonomous) • Final Year Capstone Project
    </div>
    """,
    unsafe_allow_html=True,
)
