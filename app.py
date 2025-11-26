import streamlit as st
import requests
import hashlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from fpdf import FPDF
import random

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Leak Auditor Pro",
    page_icon="🛡️",
    layout="centered"
)

# --- BACKEND LOGIC ---

def get_mock_breaches():
    """Fallback Simulation Data (Used if Real API fails)"""
    return [
        {
            "Name": "LinkedIn",
            "Domain": "linkedin.com",
            "BreachDate": "2016-05-17",
            "DataClasses": ["Email addresses", "Passwords", "Job titles"],
            "Description": "Massive networking site breach exposing 164M accounts."
        },
        {
            "Name": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Password hints", "Usernames"],
            "Description": "Adobe creative cloud user database compromise."
        },
        {
            "Name": "Zomato",
            "Domain": "zomato.com",
            "BreachDate": "2017-05-18",
            "DataClasses": ["Email addresses", "Passwords"],
            "Description": "Food delivery platform breach affecting 17 million users."
        }
    ]

def get_real_breaches(email):
    """Tries to fetch REAL data from LeakCheck Public API."""
    url = f"https://leakcheck.io/api/public?check={email}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get('success') and data.get('sources'):
            real_breaches = []
            for source in data.get('sources'):
                name = source.get('name') if isinstance(source, dict) else source
                real_breaches.append({
                    "Name": name,
                    "BreachDate": "2021-01-01", # Default date
                    "DataClasses": ["Email", "Password (Assumed)"],
                    "Description": "Confirmed entry in public leak database."
                })
            return real_breaches
        return []
    except:
        return None # Connection Error

def check_password_pwned(password):
    """Checks the Official HIBP API for passwords (Real & Free)."""
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pass[:5], sha1pass[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
    except:
        return -1
    return 0

def calculate_risk(breaches):
    score = 0
    weights = {'Passwords': 30, 'Email addresses': 10, 'Phone numbers': 50}
    for breach in breaches:
        classes = breach.get('DataClasses', ['Email', 'Password'])
        for dtype in classes:
            score += weights.get(dtype, 15)
    return min(score, 100)

def generate_pdf(email, score, breaches, leak_count):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Security Audit Report for: {email}", ln=1, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", 'B', size=14)
    pdf.cell(200, 10, txt=f"Risk Score: {score}/100", ln=1)
    
    if leak_count > 0:
        pdf.set_text_color(255, 0, 0)
        pdf.cell(200, 10, txt=f"ALERT: Test password found in {leak_count} breaches.", ln=1)
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(200, 10, txt="PASS: Test password is safe.", ln=1)
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    pdf.cell(200, 10, txt="Breach History:", ln=1)
    pdf.set_font("Arial", size=10)
    for b in breaches:
        # Sanitize text for PDF
        name = str(b['Name']).encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(0, 8, txt=f"- {name}", ln=1)
        
    pdf.output("Risk_Report.pdf")

# --- FRONTEND UI ---
st.title("🛡️ Identity Leak Auditor")
st.markdown("Check if your data has been exposed in Dark Web breaches.")
st.divider()

# Sidebar
with st.sidebar:
    st.header("Input Data")
    email_input = st.text_input("Enter Email", "demo@test.com")
    pass_input = st.text_input("Check Password (Optional)", type="password")
    if st.button("Run Audit", type="primary"):
        st.session_state['run'] = True

if st.session_state.get('run'):
    st.subheader(f"Results for: {email_input}")
    
    # 1. GET DATA
    with st.spinner("Scanning databases..."):
        breaches = get_real_breaches(email_input)
        
        # LOGIC: If real API fails or finds nothing, AND it's the demo email, switch to Mock
        if (not breaches) and (email_input == "demo@test.com"):
            breaches = get_mock_breaches()
            st.info("ℹ️ Running in **Simulation Mode** (Demo Data).")
        elif breaches:
            st.success(f"✅ Found {len(breaches)} real breaches.")
        else:
            st.success("✅ No breaches found in public databases.")
            breaches = []

    if breaches:
        # 2. RISK SCORE
        score = calculate_risk(breaches)
        c1, c2 = st.columns(2)
        c1.metric("Breaches", len(breaches))
        c2.metric("Risk Score", f"{score}/100")
        
        if score > 50: st.error("Status: HIGH RISK")
        else: st.warning("Status: MODERATE RISK")

        # 3. TIMELINE GRAPH
        st.markdown("### 📅 Breach Timeline")
        dates = []
        names = []
        for b in breaches:
            try:
                d = datetime.strptime(b.get('BreachDate', '2021-01-01'), "%Y-%m-%d")
            except:
                d = datetime(2021, 1, 1)
            dates.append(d)
            names.append(b['Name'])
            
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.stem(dates, [1]*len(dates))
        ax.get_yaxis().set_visible(False)
        st.pyplot(fig)

    # 4. PASSWORD CHECK
    if pass_input:
        st.divider()
        st.subheader("Password Analysis")
        count = check_password_pwned(pass_input)
        if count > 0:
            st.error(f"❌ DANGER: This password appears in {count:,} breaches!")
        else:
            st.success("✅ Secure: This password is safe.")
    else:
        count = 0

    # 5. REPORT
    st.divider()
    if st.button("Download PDF Report"):
        generate_pdf(email_input, score if breaches else 0, breaches, count)
        with open("Risk_Report.pdf", "rb") as f:
            st.download_button("📥 Click to Save PDF", f, "Risk_Report.pdf")