import streamlit as st
import pandas as pd
import requests
import plotly.graph_objects as go
from streamlit_folium import st_folium
import folium
from datetime import datetime
import random
from PIL import Image
from PIL.ExifTags import TAGS
import feedparser
import io
import base64
import re

# ==========================================
# 1. CONFIGURATION & THEME
# ==========================================
st.set_page_config(
    page_title="V0LTAIC // OMNISCIENCE",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Palette (inspired by ICS/industrial dashboards) ---
PRIMARY = "#38BDF8"   # cyan blue
PRIMARY_SOFT = "rgba(56,189,248,0.18)"
ACCENT = "#F97316"    # amber
BG = "#050816"        # deep navy
PANEL = "#0B1020"     # dark card
PANEL_SOFT = "#111827"
TEXT = "#E5E7EB"
TEXT_MUTED = "#9CA3AF"
BORDER = "#1F2937"

# Custom CSS
st.markdown(f"""
    <style>
        :root {{
            --primary: {PRIMARY};
            --primary-soft: {PRIMARY_SOFT};
            --accent: {ACCENT};
            --bg: {BG};
            --panel: {PANEL};
            --panel-soft: {PANEL_SOFT};
            --text: {TEXT};
            --text-muted: {TEXT_MUTED};
            --border: {BORDER};
        }}

        .stApp {{
            background-color: var(--bg);
            background-image:
                radial-gradient(circle at 0 0, rgba(148,163,184,0.18) 0, transparent 55%),
                linear-gradient(var(--panel-soft) 1px, transparent 1px),
                linear-gradient(90deg, var(--panel-soft) 1px, transparent 1px);
            background-size: auto, 40px 40px, 40px 40px;
        }}

        h1, h2, h3, h4, h5, h6 {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif !important;
            color: var(--text);
            letter-spacing: 0.16em;
            text-transform: uppercase;
        }}

        p, div, span, label {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif !important;
            color: var(--text);
        }}

        /* Sidebar */
        section[data-testid="stSidebar"] {{
            background: radial-gradient(circle at top, rgba(56,189,248,0.25), transparent 55%), #020617;
            border-right: 1px solid rgba(30,64,175,0.7);
        }}
        .sidebar-content {{
            color: var(--text);
        }}

        /* Inputs */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea {{
            background-color: #020617;
            color: var(--text);
            border-radius: 8px;
            border: 1px solid rgba(148,163,184,0.6);
        }}

        /* Buttons */
        .stButton > button {{
            background: linear-gradient(90deg, var(--primary), var(--accent));
            color: #0B1120;
            border: 0;
            border-radius: 999px;
            font-weight: 600;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }}
        .stButton > button:hover {{
            box-shadow: 0 0 18px rgba(56,189,248,0.75);
            filter: brightness(1.05);
        }}

        /* Metric cards */
        [data-testid="stMetric"] {{
            background: radial-gradient(circle at top right, rgba(56,189,248,0.25), transparent 55%), var(--panel);
            padding: 0.75rem 0.9rem;
            border-radius: 12px;
            border: 1px solid rgba(30,64,175,0.6);
        }}

        /* Feed cards */
        .feed-card {{
            border: 1px solid var(--border);
            padding: 12px 14px;
            margin-bottom: 10px;
            background: radial-gradient(circle at top left, var(--primary-soft), transparent 60%), var(--panel);
            border-left: 4px solid var(--primary);
            border-radius: 10px;
        }}
        .feed-card h3 {{
            margin-bottom: 4px;
            font-size: 0.95rem;
        }}
        .feed-card small {{
            color: var(--text-muted);
        }}
        .feed-card p {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .risk-critical {{ border-left-color: #ef4444; }}
        .risk-high {{ border-left-color: #f97316; }}

        /* Tables */
        .dataframe tbody tr:nth-child(even) {{
            background-color: rgba(15,23,42,0.85);
        }}
        .dataframe tbody tr:nth-child(odd) {{
            background-color: rgba(17,24,39,0.95);
        }}
        .dataframe thead tr {{
            background-color: #111827;
        }}

        /* Section separator */
        hr {{
            border: none;
            border-top: 1px solid rgba(55,65,81,0.8);
        }}
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. INTEL ENGINE (FUNCTIONS)
# ==========================================

def get_cisa_feed():
    """Fetch ICS / security advisories. Real RSS first, then fallback."""
    try:
        feed = feedparser.parse("https://www.cisa.gov/sites/default/files/api/v1/bulletin_items.xml")
        if feed.entries:
            data = []
            for entry in feed.entries[:10]:
                data.append({
                    "Title": entry.title,
                    "Link": entry.link,
                    "Date": entry.published if "published" in entry else "",
                    "Summary": entry.summary[:150] + "..." if "summary" in entry else "",
                })
            return data
    except Exception:
        pass

    # Fallback Mock Data
    return [
        {"Title": "ICS-ALERT-24-001: Siemens SCALANCE X-200", "Link": "#", "Date": "2024-05-12",
         "Summary": "Critical RCE vulnerability in web interface."},
        {"Title": "ICS-ALERT-24-002: Rockwell Automation Logix", "Link": "#", "Date": "2024-05-10",
         "Summary": "Denial of Service condition via CIP packets."},
        {"Title": "ICS-ALERT-24-003: Honeywell Experion PKS", "Link": "#", "Date": "2024-05-08",
         "Summary": "Improper authentication in controller."},
    ]

def analyze_image(image_file):
    """Extract EXIF metadata from uploaded images."""
    try:
        image = Image.open(image_file)
        exif_data = {}
        info = image._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                if decoded not in ("MakerNote", "UserComment"):
                    exif_data[decoded] = str(value)
        return image, exif_data
    except Exception as e:
        return None, {"Error": str(e)}

def categorize_input(user_input):
    """Auto-detects if input is IP, URL, or other string/hash."""
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    url_pattern = r"^(http|https)://|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(ip_pattern, user_input):
        return "IP_ADDRESS"
    elif re.match(url_pattern, user_input):
        return "DOMAIN/URL"
    else:
        return "STRING/HASH"

def get_threat_score(target):
    """Simulated risk scoring."""
    random.seed(target)
    score = random.randint(0, 100)
    context = []
    if score > 70:
        context = ["Dark Web Mention", "Botnet Node", "Known C2 Infrastructure"]
    elif score > 40:
        context = ["Scanner Activity", "Abuse Reports"]
    else:
        context = ["Currently Clean"]
    return score, context

# ==========================================
# 3. SESSION STATE (INVESTIGATION NOTEBOOK)
# ==========================================
if "investigation_notes" not in st.session_state:
    st.session_state.investigation_notes = []

def add_note(category, content):
    entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{category}] {content}"
    st.session_state.investigation_notes.append(entry)

# ==========================================
# 4. UI LAYOUT
# ==========================================

# Sidebar
st.sidebar.title("V0LTAIC // OMNISCIENCE")
mode = st.sidebar.radio(
    "Module",
    ["CMD_CENTER", "HUNTER_OSINT", "VISION_ANALYSIS", "CISA_WIRE", "INVESTIGATION_LOG"]
)
st.sidebar.markdown("---")
api_key = st.sidebar.text_input("API KEY (VirusTotal / Shodan)", type="password")
st.sidebar.info("SYSTEM STATUS: ONLINE")

# Header
st.title("ICS THREAT INTELLIGENCE CONSOLE")
st.markdown("---")

# -----------------------------------------
# MODULE: COMMAND CENTER
# -----------------------------------------
if mode == "CMD_CENTER":
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Global Posture", "3", delta="-1")
    col2.metric("ICS CVEs (24H)", "12", delta="3")
    col3.metric("Active Clusters", "5", delta="APT-29")
    col4.metric("Platform Health", "100%", "Nominal")

    st.subheader("Operational View")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB positron")

    # Example nodes
    coords = [
        [40.7128, -74.0060],  # New York
        [51.5074, -0.1278],   # London
        [35.6895, 139.6917],  # Tokyo
        [55.7558, 37.6173],   # Moscow
    ]
    for coord in coords:
        folium.CircleMarker(
            location=coord,
            radius=6,
            color=PRIMARY,
            fill=True,
            fill_opacity=0.9,
        ).add_to(m)
        folium.PolyLine(
            [coord, [20, 0]],
            color=ACCENT,
            weight=1.0,
            opacity=0.4,
        ).add_to(m)

    st_folium(m, width=1400, height=450)

# -----------------------------------------
# MODULE: HUNTER (OSINT)
# -----------------------------------------
elif mode == "HUNTER_OSINT":
    st.subheader("Unified Threat Search")

    col_search, col_btn = st.columns([4, 1])
    target = col_search.text_input(
        "Artifact (IP / Domain / Hash)",
        placeholder="192.0.2.10 or example.com"
    )
    run_scan = col_btn.button("Execute Scan")

    if run_scan and target:
        input_type = categorize_input(target)
        st.markdown(f"**Detected Type:** `{input_type}`")
        add_note("OSINT", f"Scanned target: {target} ({input_type})")

        score, context = get_threat_score(target)

        c1, c2 = st.columns([1, 2])

        with c1:
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": "Risk Score"},
                gauge={
                    "axis": {"range": [None, 100]},
                    "bar": {"color": PRIMARY if score < 60 else ACCENT},
                    "bordercolor": "#1F2937",
                    "bgcolor": "#020617",
                },
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": TEXT, "family": "system-ui"},
            )
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("### Context")
            st.write(f"**Target:** {target}")
            st.write(f"**Tags:** {', '.join(context)}")

            st.markdown("#### Observed Surface (Simulated)")
            ports = [80, 443]
            if input_type == "IP_ADDRESS" and score > 50:
                ports += [502, 102]  # OT ports when higher risk

            st.code(
                f"OPEN PORTS: {ports}\nBANNER: Apache/2.4.41 (Ubuntu) | Modbus/TCP",
                language="bash",
            )

            st.markdown("#### External Pivot Links")
            st.markdown(f"[VirusTotal Search](https://www.virustotal.com/gui/search/{target})")
            st.markdown(f"[Shodan Search](https://www.shodan.io/search?query={target})")
            st.markdown(f"[AbuseIPDB](https://www.abuseipdb.com/check/{target})")

# -----------------------------------------
# MODULE: VISION (IMAGE INTEL)
# -----------------------------------------
elif mode == "VISION_ANALYSIS":
    st.subheader("Optical Reconnaissance")
    st.markdown("Upload imagery for metadata extraction and reverse-search pivoting.")

    uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png", "jpeg"])

    if uploaded_file:
        col_img, col_data = st.columns(2)

        img, metadata = analyze_image(uploaded_file)

        with col_img:
            if img is not None:
                st.image(img, caption="Artifact", use_container_width=True)
            else:
                st.error("Unable to render image.")

        with col_data:
            st.markdown("### Metadata")
            if metadata:
                df_meta = pd.DataFrame.from_dict(metadata, orient="index", columns=["Value"])
                st.dataframe(df_meta, height=300)
                add_note("VISION", f"Analyzed image {uploaded_file.name}. Found {len(metadata)} metadata tags.")
            else:
                st.warning("No metadata recovered (possibly stripped).")

            st.markdown("### Reverse Search Links")
            st.markdown("[Google Images](https://images.google.com/)")
            st.markdown("[Yandex Images](https://yandex.com/images/)")
            st.markdown("[TinEye](https://tineye.com/)")

# -----------------------------------------
# MODULE: CISA WIRE (FEED)
# -----------------------------------------
elif mode == "CISA_WIRE":
    st.subheader("ICS Advisory Wire")

    col1, col2 = st.columns([3, 1])
    with col1:
        feed_data = get_cisa_feed()
        search_feed = st.text_input("Filter feed", "")

        for item in feed_data:
            if search_feed.lower() in item["Title"].lower() or search_feed.lower() in item["Summary"].lower():
                severity_class = "feed-card"
                if "critical" in item["Summary"].lower():
                    severity_class += " risk-critical"
                elif "high" in item["Summary"].lower():
                    severity_class += " risk-high"

                st.markdown(f"""
                    <div class="{severity_class}">
                        <h3><a href="{item['Link']}" target="_blank" style="text-decoration:none; color:{PRIMARY};">
                            {item['Title']}
                        </a></h3>
                        <small>{item['Date']}</small>
                        <p>{item['Summary']}</p>
                    </div>
                """, unsafe_allow_html=True)

    with col2:
        st.markdown("### Vendor Watchlist")
        st.checkbox("Siemens", value=True)
        st.checkbox("Schneider Electric", value=True)
        st.checkbox("Rockwell Automation", value=True)
        st.checkbox("Honeywell", value=True)

        st.markdown("---")
        st.metric("Advisories Today", "4")

# -----------------------------------------
# MODULE: INVESTIGATION LOG
# -----------------------------------------
elif mode == "INVESTIGATION_LOG":
    st.subheader("Case File Builder")

    note_text = st.text_area("Add note", key="manual_note_input")
    if st.button("Add Note"):
        if note_text:
            add_note("MANUAL", note_text)

    st.markdown("---")
    st.markdown("### Current Session Log")

    if st.session_state.investigation_notes:
        report_text = "\n".join(st.session_state.investigation_notes)
        st.text_area("Logs", value=report_text, height=400)

        st.download_button(
            label="Export Case Report (.txt)",
            data=report_text,
            file_name=f"VOLTAIC_REPORT_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain",
        )
    else:
        st.info("No notes in this session yet.")

# Footer
st.markdown("---")
st.markdown(
    "<center>V0LTAIC // OMNISCIENCE MODULE // SESSION ACTIVE</center>",
    unsafe_allow_html=True,
)
