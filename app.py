import streamlit as st
import requests
import hashlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from fpdf import FPDF

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberSentinel Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. CUSTOM CSS (THE BEAUTIFUL PART) ---
st.markdown("""
<style>
    /* THE BACKGROUND GRADIENT */
    .stApp {
        background: linear-gradient(135deg, #74ebd5 0%, #ACB6E5 100%);
        background-attachment: fixed;
    }
    
    /* DASHBOARD TITLE */
    h1 {
        color: #2c3e50;
        text-align: center;
        font-family: 'Helvetica', sans-serif;
        font-weight: 800;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    
    /* METRIC CARDS (Glass Effect) */
    div[data-testid="stMetric"] {
        background-color: rgba(255, 255, 255, 0.6);
        border-radius: 15px;
        padding: 20px;
        border: 1px solid rgba(255,255,255, 0.5);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        backdrop-filter: blur(10px);
        text-align: center;
    }
    
    /* BUTTON STYLING */
    .stButton>button {
        width: 100%;
        border-radius: 50px;
        height: 3em;
        background: linear-gradient(90deg, #FF4B4B 0%, #FF9068 100%);
        color: white;
        font-weight: bold;
        border: none;
        box-shadow: 0 4px 15px rgba(255, 75, 75, 0.4);
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(255, 75, 75, 0.6);
    }

    /* TABS Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: rgba(255,255,255,0.5);
        border-radius: 10px;
        padding-left: 20px;
        padding-right: 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #fff;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# --- 3. BACKEND LOGIC ---
def get_mock_breaches():
    return [
        {"Name": "LinkedIn", "BreachDate": "2016-05-17", "DataClasses": ["Email", "Passwords", "Job titles"], "Description": "164 Million accounts exposed in massive professional network hack."},
        {"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email", "Hints", "Usernames"], "Description": "153 Million accounts exposed affecting Creative Cloud users."},
        {"Name": "Zomato", "BreachDate": "2017-05-18", "DataClasses": ["Email", "Passwords"], "Description": "17 Million user records leaked from food delivery giant."},
        {"Name": "Canva", "BreachDate": "2019-05-24", "DataClasses": ["Email", "Names", "Locations"], "Description": "Graphic design platform database compromised."}
    ]

def get_real_breaches(email):
    url = f"https://leakcheck.io/api/public?check={email}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get('success') and data.get('sources'):
            real_breaches = []
            for source in data.get('sources'):
                name = source.get('name') if isinstance(source, dict) else source
                real_breaches.append({
                    "Name": name, "BreachDate": "2021-01-01", 
                    "DataClasses": ["Email", "Password"], "Description": "Public Database Leak"
                })
            return real_breaches
        return []
    except:
        return None

def check_password_pwned(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pass[:5], sha1pass[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(':')
                if h == suffix: return int(count)
    except: return -1
    return 0

def calculate_risk(breaches):
    score = 0
    weights = {'Passwords': 30, 'Email': 10, 'Phone': 50}
    for b in breaches:
        for dtype in b.get('DataClasses', []):
            score += weights.get(dtype, 15)
    return min(score, 100)

def generate_pdf(email, score, breaches):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, 'CyberSentinel Audit Report', 0, 1, 'C')
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.cell(0, 10, f"Target: {email}", 0, 1)
    pdf.cell(0, 10, f"Risk Score: {score}/100", 0, 1)
    pdf.ln(10)
    pdf.cell(0, 10, "Breach History:", 0, 1)
    pdf.set_font("Arial", size=10)
    for b in breaches:
        pdf.cell(0, 8, f"- {b['Name']}", 0, 1)
    pdf.output("Risk_Report.pdf")

# --- 4. THE UI LAYOUT ---

# Header
st.markdown("<h1>🛡️ CyberSentinel <br><span style='font-size: 20px; color: #555;'>Advanced Identity Leak Auditor</span></h1>", unsafe_allow_html=True)
st.divider()

# Sidebar
with st.sidebar:
    st.markdown("### ⚙️ Control Panel")
    email_input = st.text_input("Target Email Address", "demo@test.com")
    pass_input = st.text_input("Password Check (Optional)", type="password")
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 INITIATE SCAN"):
        st.session_state['run'] = True
    
    st.markdown("---")
    st.caption("🔒 Zero-Knowledge Architecture. \nYour password is never sent fully.")

# Main Dashboard
if st.session_state.get('run'):
    
    # FETCH DATA
    with st.spinner("🕵️ Scouring Dark Web Databases..."):
        breaches = get_real_breaches(email_input)
        is_sim = False
        if not breaches and email_input == "demo@test.com":
            breaches = get_mock_breaches()
            is_sim = True
        
        risk_score = calculate_risk(breaches) if breaches else 0

    # ALERT BANNER
    if risk_score > 50:
        st.error(f"🚨 CRITICAL THREAT DETECTED: Risk Score {risk_score}/100")
    elif risk_score > 0:
        st.warning(f"⚠️ MODERATE RISK: Risk Score {risk_score}/100")
    else:
        st.success("✅ SYSTEM SECURE: No data breaches found.")

    if is_sim:
        st.caption("ℹ️ Running in Simulation Mode for Demonstration")

    # TABS
    tab1, tab2, tab3 = st.tabs(["📊 Live Dashboard", "🕸️ Attack Map", "🔑 Password Lab"])

    with tab1:
        # METRICS ROW
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Breaches", len(breaches) if breaches else 0)
        col2.metric("Identity Risk Score", f"{risk_score}/100", delta="High Risk" if risk_score > 50 else "Safe")
        col3.metric("Data Source", "Simulation" if is_sim else "Live API")

        st.markdown("### 📜 Forensic Log")
        if breaches:
            for b in breaches:
                with st.expander(f"🔴 {b['Name']} ({b.get('BreachDate', 'N/A')})"):
                    st.write(f"**Description:** {b.get('Description', 'No details available.')}")
                    st.write(f"**Compromised Data:** {', '.join(b.get('DataClasses', []))}")
        else:
            st.info("No breaches to display.")

    with tab2:
        st.markdown("### 📅 Timeline of Compromise")
        if breaches:
            dates = [datetime.strptime(b.get('BreachDate', '2021-01-01'), "%Y-%m-%d") for b in breaches]
            names = [b['Name'] for b in breaches]
            
            fig, ax = plt.subplots(figsize=(10, 4))
            fig.patch.set_alpha(0) # Transparent chart background
            ax.patch.set_alpha(0)
            
            # Stylish Stem Plot
            markerline, stemline, baseline = ax.stem(dates, [1]*len(dates))
            plt.setp(markerline, marker='D', markersize=8, markeredgecolor="#FF4B4B", markerfacecolor="white")
            plt.setp(stemline, color='#2c3e50', linestyle='--')
            
            ax.get_yaxis().set_visible(False)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['left'].set_visible(False)
            ax.spines['bottom'].set_color('#2c3e50')
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
            
            for d, name in zip(dates, names):
                ax.annotate(name, xy=(d, 1.1), xytext=(0, 5), textcoords="offset points", ha='center', fontweight='bold', color="#2c3e50")
            
            st.pyplot(fig)
        else:
            st.info("No timeline data available.")

    with tab3:
        st.markdown("### 🔐 Password Strength & Exposure Analysis")
        if pass_input:
            leaks = check_password_pwned(pass_input)
            colA, colB = st.columns([1, 2])
            with colA:
                if leaks > 0:
                    st.markdown("# ⚠️")
                else:
                    st.markdown("# ✅")
            with colB:
                if leaks > 0:
                    st.error(f"This password has been exposed **{leaks:,}** times in global data breaches.")
                    st.markdown("**Recommendation:** CHANGE IMMEDIATELY.")
                elif leaks == 0:
                    st.success("This password has NOT been found in known leaks.")
                else:
                    st.warning("Could not connect to analysis server.")
        else:
            st.info("Enter a password in the sidebar to test its exposure.")

    # REPORT GENERATION
    st.divider()
    if st.button("📄 Export Forensic PDF Report"):
        generate_pdf(email_input, risk_score, breaches if breaches else [])
        with open("Risk_Report.pdf", "rb") as f:
            st.download_button("📥 Download PDF", f, "Risk_Report.pdf")

else:
    # LANDING PAGE STATE
    st.info("👈 Enter an email in the sidebar and click 'INITIATE SCAN' to begin.")
