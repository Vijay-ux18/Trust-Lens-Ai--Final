"""
Dashboard page for TrustLens AI.
Displays session-specific analysis statistics, risk distributions,
and history of scanned files.
"""

import pandas as pd
import plotly.express as px
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="TrustLens AI - Security Operations Dashboard",
    page_icon="📊",
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
    
    /* Premium Stats Cards Grid */
    .stat-card-grid {
        display: flex;
        gap: 1.2rem;
        margin-bottom: 2rem;
    }
    
    .stat-card {
        flex: 1;
        background: #ffffff;
        border: 1px solid #f1f5f9;
        box-shadow: 0 4px 12px rgba(15,23,42,0.02);
        padding: 24px;
        border-radius: 16px;
        border-top: 5px solid #6366f1;
        text-align: center;
    }
    
    .stat-card.safe { border-top-color: #10b981; }
    .stat-card.suspicious { border-top-color: #f59e0b; }
    .stat-card.danger { border-top-color: #ef4444; }
    
    .stat-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        color: #64748b;
        letter-spacing: 0.05em;
    }
    
    .stat-value {
        font-family: 'Outfit', sans-serif;
        font-size: 2.5rem;
        font-weight: 800;
        color: #0f172a;
        margin-top: 0.25rem;
    }
    
    /* Layout Framing */
    .dash-box {
        background: #ffffff;
        border: 1px solid #f1f5f9;
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 4px 12px rgba(15,23,42,0.02);
        margin-bottom: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<h1 class='page-title'>📊 Security Operations Dashboard</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='page-desc'>Review real-time threat telemetry, risk distributions, and compliance history compiled during your active analysis session.</p>",
    unsafe_allow_html=True,
)

# Sidebar branding card
st.sidebar.markdown(
    """
    <div style='background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); padding: 20px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; text-align: center;'>
        <div style='font-size: 2.2rem; margin-bottom: 8px;'>📊</div>
        <h3 style='font-family: Outfit; font-weight: 800; color: #0f172a; margin: 0; font-size: 1.4rem;'>Ops Center</h3>
        <span style='color: #64748b; font-size: 0.85rem;'>Real-Time Session Logs</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# Verify session state history exists
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

scan_count = len(st.session_state.scan_history)

if scan_count == 0:
    # Beautiful Empty State Card
    st.markdown(
        """
        <div style='text-align: center; padding: 4rem 2rem; background-color: #f8fafc; border-radius: 16px; border: 2px dashed #cbd5e1; margin-top: 1rem;'>
            <div style='font-size: 3rem; margin-bottom: 1rem;'>📊</div>
            <h3 style='font-family: Outfit; font-weight: 600; color: #475569; margin: 0;'>No Active Scan History</h3>
            <p style='color: #64748b; margin-top: 0.5rem;'>Please navigate to the <strong>Upload & Predict</strong> page and run threat checks to populate statistics.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    # 1. Statistical calculations
    safe_count = sum(
        1 for item in st.session_state.scan_history if item.get("risk_category") in ["Safe", "Low"]
    )
    suspicious_count = sum(
        1 for item in st.session_state.scan_history if item.get("risk_category") == "Medium"
    )
    high_risk_count = sum(
        1 for item in st.session_state.scan_history if item.get("risk_category") in ["High", "Critical"]
    )

    # Render Premium Stat Cards
    st.markdown(
        f"""
        <div class="stat-card-grid">
            <div class="stat-card">
                <div class="stat-label">Total Scans</div>
                <div class="stat-value">{scan_count}</div>
            </div>
            <div class="stat-card safe">
                <div class="stat-label">Safe & Low Risk</div>
                <div class="stat-value" style="color: #10b981;">{safe_count}</div>
            </div>
            <div class="stat-card suspicious">
                <div class="stat-label">Suspicious</div>
                <div class="stat-value" style="color: #f59e0b;">{suspicious_count}</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-label">High & Critical</div>
                <div class="stat-value" style="color: #ef4444;">{high_risk_count}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Risk Distribution & Recent History Rows
    col_left, col_right = st.columns([1, 1.2], gap="large")

    with col_left:
        st.markdown("<h3 style='font-family: Outfit; font-weight: 700; font-size: 1.4rem; color: #f8fafc !important; margin-bottom: 1.2rem;'>🎯 Risk Profile Distribution</h3>", unsafe_allow_html=True)
        
        levels = ["Safe & Low", "Suspicious (Medium)", "High & Critical"]
        counts = [safe_count, suspicious_count, high_risk_count]
        df_dist = pd.DataFrame({"Risk Group": levels, "Count": counts})

        fig_dist = px.pie(
            df_dist,
            values="Count",
            names="Risk Group",
            color="Risk Group",
            color_discrete_map={
                "Safe & Low": "#10b981",
                "Suspicious (Medium)": "#f59e0b",
                "High & Critical": "#ef4444",
            },
            hole=0.45,
        )
        fig_dist.update_traces(
            textposition="inside", 
            textinfo="percent+label",
            marker=dict(line=dict(color='#ffffff', width=2))
        )
        fig_dist.update_layout(
            showlegend=False, 
            margin=dict(t=15, b=15, l=15, r=15), 
            height=300,
            paper_bgcolor="rgba(0,0,0,0)",
        )
        
        st.plotly_chart(fig_dist, use_container_width=True)

    with col_right:
        st.markdown("<h3 style='font-family: Outfit; font-weight: 700; font-size: 1.4rem; color: #f8fafc !important; margin-bottom: 1.2rem;'>📜 Active Session History</h3>", unsafe_allow_html=True)
        
        records = []
        for item in reversed(st.session_state.scan_history):
            records.append(
                {
                    "File Name": item["filename"],
                    "Detected Format": item["file_type"],
                    "Size": item["file_size"],
                    "Trust Score": f"{item['trust_score']:.1f}%",
                    "Risk Index": item.get("risk_category", "Low"),
                }
            )

        df_history = pd.DataFrame(records)
        st.dataframe(df_history, use_container_width=True, hide_index=True)
