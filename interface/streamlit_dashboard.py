"""
interface/streamlit_dashboard.py - Web UI

FIX: Scan page ENFORCES SCOPE via core.scope_guard.
Run: streamlit run interface/streamlit_dashboard.py
"""

import sys
from pathlib import Path

# Add root to path
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
import pandas as pd
import plotly.express as px

from core.config import CONFIG, get_tool_count, KALI_TOOLS
from core.scope_guard import validate_scope   # ← NEW: scope enforcement
from intelligence.cve_feed import CVEFeed

# ─── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title="Cyber Jarvis v6.0",
    page_icon="🔴",
    layout="wide",
)

st.markdown("""
<style>
    .main-header { font-size: 3rem; color: #ff2b2b; text-align: center; font-weight: bold; }
    .sub-header { text-align: center; color: #888; font-size: 1.1rem; }
</style>
""", unsafe_allow_html=True)


# ─── Session state ─────────────────────────────────────────
for k, v in {
    "findings": [],
    "cve_data": None,
    "scan_history": [],
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─── Sidebar ───────────────────────────────────────────────
st.sidebar.markdown("# 🔴 Cyber Jarvis v6.0")
st.sidebar.markdown(f"**Language**: `{CONFIG['language']}`")
st.sidebar.markdown(f"**WhatsApp**: `{CONFIG['whatsapp_number']}`")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    ["🏠 Dashboard", "🎯 Scan Target", "📰 CVE News",
     "🛠️ Tools", "📊 Findings", "⚙️ Settings"],
)


# ═══════════════════════════════════════════════════════════
#  Dashboard
# ═══════════════════════════════════════════════════════════
if page == "🏠 Dashboard":
    st.markdown('<p class="main-header">🔴 CYBER JARVIS</p>', unsafe_allow_html=True)
    st.markdown(
        f'<p class="sub-header">Language: {CONFIG["language"]} · v6.0</p>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🛠️ Tools", get_tool_count())
    col2.metric("📊 Findings", len(st.session_state.findings))
    col3.metric("📱 WhatsApp", CONFIG["whatsapp_number"])
    col4.metric("🌐 Language", CONFIG["language"].upper())

    st.markdown("### 🚀 Quick Actions")
    col_a, col_b = st.columns(2)

    with col_a:
        if st.button("📰 Fetch Latest CVEs", use_container_width=True):
            with st.spinner("Fetching from NVD..."):
                feed = CVEFeed()
                cves = feed.fetch_recent_cves(days=7)
                st.session_state.cve_data = cves
                st.success(f"Found {len(cves)} CVEs")

    with col_b:
        if st.button("📊 View Report Folder", use_container_width=True):
            st.info(f"Reports at: {CONFIG['reports_dir']}")


# ═══════════════════════════════════════════════════════════
#  Scan Target (SCOPE-ENFORCED)
# ═══════════════════════════════════════════════════════════
elif page == "🎯 Scan Target":
    st.markdown("## 🎯 Scan Target")

    target = st.text_input(
        "Target (URL / IP / Domain)",
        placeholder="example.com or 192.168.1.10",
    )

    scan_type = st.selectbox(
        "Scan Type",
        ["Nmap (port scan)", "Nuclei (vuln scan)", "Burp (web scan)"],
    )

    # ─── SCOPE VALIDATION PREVIEW ─────────────────────────
    if target:
        allowed, reason = validate_scope(target)
        if allowed:
            st.success(f"✅ Scope OK — {reason}")
        else:
            st.error(f"❌ Scope DENIED — {reason}")
            st.info(
                "Add to `workspace/scope.txt`:\n"
                "```\n"
                f"{target}\n"
                "```"
            )

    if st.button("🚀 Run Scan", use_container_width=True):
        if not target:
            st.warning("Enter a target first")
        else:
            allowed, reason = validate_scope(target)
            if not allowed:
                st.error(f"❌ SCOPE DENIED: {reason}")
                st.stop()  # ← CRITICAL: block execution

            # Only reach here if scope allows
            st.info(f"Starting {scan_type} on {target}...")

            try:
                if scan_type.startswith("Nmap"):
                    from core.tools_engine import RemoteToolExecutor
                    result = RemoteToolExecutor.execute(
                        "nmap", ["-sV", "-T4", target], target,
                    )
                    st.code(result.get("output", "")[:3000])

                elif scan_type.startswith("Nuclei"):
                    from tools_integration.nuclei_manager import NucleiManager
                    result = NucleiManager().scan(target)
                    st.success(f"Nuclei findings: {result.get('total_findings', 0)}")

                elif scan_type.startswith("Burp"):
                    from tools_integration.burp_api import BurpAPI
                    burp = BurpAPI()
                    if burp.is_ready():
                        result = burp.full_scan(target)
                        st.success(f"Burp issues: {result.get('total_issues', 0)}")
                    else:
                        st.error("Burp REST API not available")

                st.session_state.scan_history.append({
                    "target": target,
                    "type": scan_type,
                })
            except Exception as e:
                st.error(f"Scan failed: {e}")


# ═══════════════════════════════════════════════════════════
#  CVE News
# ═══════════════════════════════════════════════════════════
elif page == "📰 CVE News":
    st.markdown("## 📰 CVE & Cyber News")

    if st.button("🔄 Fetch Latest"):
        with st.spinner("Fetching from NVD + RSS..."):
            feed = CVEFeed()
            st.session_state.cve_data = feed.fetch_recent_cves(days=7)

    if st.session_state.cve_data:
        df = pd.DataFrame(st.session_state.cve_data)
        if not df.empty:
            sev_counts = df["severity"].value_counts()
            fig = px.bar(
                x=sev_counts.index,
                y=sev_counts.values,
                title="CVEs by Severity",
                color=sev_counts.index,
                color_discrete_map={
                    "CRITICAL": "#ff2b2b", "HIGH": "#ff8800",
                    "MEDIUM": "#ffdd00", "LOW": "#44dd44",
                },
            )
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(
                df[["id", "severity", "cvss_score", "description"]],
                use_container_width=True,
            )


# ═══════════════════════════════════════════════════════════
#  Tools
# ═══════════════════════════════════════════════════════════
elif page == "🛠️ Tools":
    st.markdown(f"## 🛠️ Kali Tools Database ({get_tool_count()} tools)")

    category = st.selectbox("Category", list(KALI_TOOLS.keys()))
    tools = KALI_TOOLS[category]

    st.markdown(f"### {category} ({len(tools)} tools)")
    cols = st.columns(3)
    for i, tool in enumerate(tools):
        with cols[i % 3]:
            st.markdown(f"- `{tool}`")


# ═══════════════════════════════════════════════════════════
#  Findings
# ═══════════════════════════════════════════════════════════
elif page == "📊 Findings":
    st.markdown("## 📊 Findings")

    if not st.session_state.findings:
        st.info("No findings yet. Run a scan first.")
    else:
        df = pd.DataFrame(st.session_state.findings)
        st.dataframe(df, use_container_width=True)


# ═══════════════════════════════════════════════════════════
#  Settings
# ═══════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.markdown("## ⚙️ Settings")

    st.json({
        "language": CONFIG["language"],
        "whatsapp_number": CONFIG["whatsapp_number"],
        "whatsapp_method": CONFIG["whatsapp_method"],
        "workspace": str(CONFIG["workspace"]),
        "reports_dir": str(CONFIG["reports_dir"]),
        "screenshots_dir": str(CONFIG["screenshots_dir"]),
        "scope_file": str(CONFIG["workspace"] / CONFIG["scope_file"]),
    })

    st.markdown("### 📋 scope.txt Contents")
    scope_file = CONFIG["workspace"] / CONFIG["scope_file"]
    if scope_file.exists():
        st.code(scope_file.read_text(), language="text")
    else:
        st.warning("scope.txt not found")