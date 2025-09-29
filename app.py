import streamlit as st
from detection_rules import AttackDetector, DetectionResult
from typing import Optional, Dict, Any, List

def render_result(result: DetectionResult) -> None:
    """Render the detection result in a formatted way.
    
    Args:
        result: The detection result to display
    """
    if result is None:
        st.warning("No result to display")
        return
        
    # Determine the result color based on detection status
    if result.detected:
        status_color = "#d32f2f"  # Red for detected threats
        status_icon = "🔴"
    else:
        status_color = "#388e3c"  # Green for no threats
        status_icon = "✅"
    
    # Create a container for the result
    with st.container():
        st.markdown(f"""
            <div style='background-color: {'rgba(211, 47, 47, 0.1)' if result.detected else 'rgba(56, 142, 60, 0.1)'};
                        padding: 1.5rem;
                        border-radius: 10px;
                        border-left: 4px solid {status_color};
                        margin: 1rem 0;'>
                <div style='display: flex; align-items: center; margin-bottom: 0.5rem;'>
                    <span style='font-size: 1.5rem; margin-right: 0.5rem;'>{status_icon}</span>
                    <h3 style='margin: 0; color: {status_color};'>
                        {'Threat Detected!' if result.detected else 'No Threats Detected'}
                    </h3>
                </div>
                <p style='margin-bottom: 0.5rem;'><strong>Confidence:</strong> {getattr(result, 'confidence_percent', 0):.1f}%</p>
                <p style='margin-bottom: 0.5rem;'><strong>Matched Rules:</strong> {', '.join(getattr(result, 'matched_rules', [])) or 'None'}</p>
                <div style='margin-top: 1rem;'><strong>Evidence:</strong>
                    <pre style='background: rgba(0,0,0,0.02); padding: 0.5rem; border-radius: 5px; font-size: 0.85em;'>
{chr(10).join(f'{k}: {v}' for k, v in getattr(result, 'evidence', {}).items())}
                    </pre>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        # Show recommended actions if available
        if hasattr(result, 'recommended_actions') and result.recommended_actions:
            with st.expander("🚨 Recommended Actions", expanded=True):
                for i, action in enumerate(result.recommended_actions, 1):
                    st.markdown(f"{i}. {action}")
        
        # Show additional data if available
        if hasattr(result, 'additional_data') and result.additional_data:
            with st.expander("📊 Additional Information", expanded=False):
                if isinstance(result.additional_data, dict):
                    for key, value in result.additional_data.items():
                        st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
                else:
                    st.write(result.additional_data)

# Page configuration
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for modern UI
st.markdown("""
    <style>
    /* Modern gradient background */
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #e4e8f0 100%);
        min-height: 100vh;
    }
    
    /* Sidebar styling */
    .css-1d391kg, .css-1d391kg > div:first-child {
        background: linear-gradient(180deg, #1a237e 0%, #283593 100%) !important;
        color: white !important;
    }
    
    .css-1d391kg h1, .css-1d391kg h2, .css-1d391kg h3, .css-1d391kg h4, .css-1d391kg h5, .css-1d391kg h6 {
        color: white !important;
        text-shadow: 0 1px 2px rgba(0,0,0,0.3);
    }
    
    /* Select box styling */
    .stSelectbox > div > div {
        background-color: rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
        transition: all 0.3s ease !important;
    }
    
    .stSelectbox > div > div:hover {
        background-color: rgba(255, 255, 255, 0.15) !important;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    
    .stSelectbox > label {
        color: #000000 !important;
        font-weight: 500;
    }
    
    /* Main content card */
    .main-content {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 15px;
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid rgba(255, 255, 255, 0.3);
        margin: 1rem 0;
        transition: all 0.3s ease;
    }
    
    .main-content:hover {
        box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.15);
        transform: translateY(-2px);
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #1a237e 0%, #283593 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.6rem 1.5rem !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 12px rgba(26, 35, 126, 0.2) !important;
    }
    
    /* Input fields */
    .stTextInput > div > div > input, 
    .stTextArea > div > div > textarea,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > div {
        border-radius: 10px !important;
        border: 1px solid #e0e0e0 !important;
        transition: all 0.3s ease !important;
    }
    
    .stTextInput > div > div > input:focus, 
    .stTextArea > div > div > textarea:focus,
    .stNumberInput > div > div > input:focus {
        border-color: #1a237e !important;
        box-shadow: 0 0 0 2px rgba(26, 35, 126, 0.2) !important;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #1a237e !important;
        position: relative;
        display: inline-block;
    }
    
    h1::after, h2::after, h3::after {
        content: '';
        position: absolute;
        width: 50px;
        height: 4px;
        background: linear-gradient(90deg, #1a237e, #5c6bc0);
        bottom: -10px;
        left: 0;
        border-radius: 2px;
    }
    
    /* Expanders */
    .stExpander {
        background: rgba(255, 255, 255, 0.7) !important;
        border-radius: 10px !important;
        border: 1px solid rgba(0, 0, 0, 0.1) !important;
        margin: 1rem 0 !important;
        transition: all 0.3s ease !important;
    }
    
    .stExpander:hover {
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1) !important;
    }
    
    .stExpander .st-emotion-cache-1h9l7u0 {
        background-color: rgba(26, 35, 126, 0.05) !important;
        border-radius: 10px 10px 0 0 !important;
    }
    
    /* Footer styles */
    .footer-container {
        margin-top: 3rem;
        text-align: center;
        padding: 1.5rem;
        background: rgba(26, 35, 126, 0.02);
        border-radius: 10px;
        border-top: 1px solid rgba(0,0,0,0.05);
    }
    
    .footer-text {
        color: #666;
        margin: 0;
        font-size: 0.9rem;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #c5cae9;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #9fa8da;
    }
    
    /* Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .main-content, .stExpander {
        animation: fadeIn 0.5s ease-out forwards;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .main-content {
            padding: 1rem;
        }
        
        h1 { font-size: 1.8rem !important; }
        h2 { font-size: 1.5rem !important; }
        h3 { font-size: 1.2rem !important; }
    }
    </style>
""", unsafe_allow_html=True)


# Initialize the detector
detector = AttackDetector()

# Sidebar for navigation
with st.sidebar:
    st.markdown("""
        <div style='text-align: center; margin-bottom: 2rem;'>
            <h1 style='color: white; margin-bottom: 0.5rem;'>🛡️ CyberShield AI</h1>
            <div style='height: 3px; background: linear-gradient(90deg, #ffffff, #c5cae9); margin: 0 auto 1rem; width: 50%; border-radius: 3px;'></div>
            <p style='color: #000000; font-size: 0.9rem; font-weight: 500;'>Advanced threat detection system for identifying cyber attacks</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    attack_type = st.selectbox(
        "Select Attack Type",
        [
            "Ransomware",
            "Brute Force",
            "Phishing",
            "DDoS/Traffic Flood",
            "Man-in-the-Middle (MITM)",
            "SQL Injection"
        ],
        key="attack_type_selector"
    )
    
    # Add guidance for the selected attack type
    st.markdown("<div style='margin: 1rem 0; padding: 1rem; background: rgba(0,0,0,0.05); border-radius: 8px;'>", unsafe_allow_html=True)
    
    if attack_type == "Ransomware":
        st.markdown("""
        **Test with these values to trigger detection:**
        - Files modified: > 50 in 60s
        - Entropy score: > 0.8 (indicates encryption)
        - Ransom note found: Yes
        
        *Example: 100 files modified in 30s with high entropy will trigger detection.*
        """)
    elif attack_type == "Brute Force":
        st.markdown("""
        **Test with these values to trigger detection:**
        - Failed attempts: > 5 in 5 minutes
        - Username enumeration: Yes
        - Account lockout: No
        
        *Example: 10 failed login attempts in 2 minutes will trigger detection.*
        """)
    elif attack_type == "Phishing":
        st.markdown("""
        **Test with these values to trigger detection:**
        - Suspicious links: Present
        - Urgent action: Required
        - Suspicious sender: Yes
        
        *Example: Email with 'urgent action required' and suspicious link will trigger detection.*
        """)
    elif attack_type == "DDoS/Traffic Flood":
        st.markdown("""
        **Test with these values to trigger detection:**
        - Requests per second: > 1000
        - Traffic sources: Multiple
        - Request pattern: Repetitive
        
        *Example: 2000 requests/second from multiple IPs will trigger detection.*
        """)
    elif attack_type == "Man-in-the-Middle (MITM)":
        st.markdown("""
        **Test with these values to trigger detection:**
        - SSL/TLS anomalies: Present
        - ARP spoofing: Detected
        - Certificate issues: Found
        
        *Example: Invalid or self-signed certificates will trigger detection.*
        """)
    elif attack_type == "SQL Injection":
        st.markdown("""
        **Test with these values to trigger detection:**
        - Suspicious SQL patterns: Found
        - Error messages: Reveal DB info
        - Unusual DB queries: Detected
        
        *Example: Input containing 'OR 1=1' will trigger detection.*
        """)
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("""
        <div style='text-align: center; margin-top: 2rem; color: rgba(255,255,255,0.7); font-size: 0.85rem;'>
            <p>© 2023 CyberShield AI</p>
            <p style='font-size: 0.8rem;'>Advanced Threat Detection System</p>
        </div>
    """, unsafe_allow_html=True)

# Main content container
st.markdown(f"""
    <div class='main-content'>
        <h1 style='margin-top: 0;'>{attack_type} Detection</h1>
        <div style='height: 3px; background: linear-gradient(90deg, #1a237e, #5c6bc0); margin-bottom: 1.5rem; border-radius: 3px; width: 100px;'></div>
    </div>
""", unsafe_allow_html=True)


# Define attack types
attack_types = [
    "Ransomware",
    "Brute Force",
    "Phishing",
    "DDoS/Traffic Flood",
    "Man-in-the-Middle (MITM)",
    "SQL Injection"
]

# Initialize session state for attack type
if 'attack_type' not in st.session_state:
    st.session_state.attack_type = attack_types[0]

# Navigation buttons
st.markdown("""
    <style>
    /* Main background */
    .stApp {
        background: #f5f7fa;
    }
    
    /* Navigation buttons */
    .nav-buttons {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 2rem;
        flex-wrap: wrap;
    }
    
    .nav-button {
        background: #1a237e;
        color: white !important;
        padding: 0.6rem 1.2rem;
        border-radius: 8px;
        text-decoration: none;
        font-weight: 500;
        transition: all 0.2s;
        border: none;
        cursor: pointer;
    }
    
    .nav-button:hover {
        transform: translateY(-1px);
    }
    
    .nav-button.active {
        background: #1a237e;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        border-radius: 8px !important;
        padding: 0.6rem 1.5rem !important;
        font-weight: 500 !important;
    }
    
{{ ... }}
# Navigation buttons
st.markdown('<div class="nav-buttons">' + 
            ''.join([f'<a class="nav-button{" active" if st.session_state.attack_type == at else ""}" '
                    f'href="#" onclick="window.streamlitApi.runScript(\'st.session_state.attack_type = \'{at}\'\')">{at}</a>'
                    for at in attack_types]) + 
      # Close the main content div
    st.markdown('</div>', unsafe_allow_html=True)

attack_type = st.session_state.attack_type

# Main content
with st.container():
{{ ... }}
    st.markdown(f'<div class="main-content">', unsafe_allow_html=True)
    st.title(f"{attack_type} Detection")
    st.markdown("---")

def render_result(result):
    # Result card
    with st.container():
        st.header(f"{attack_type} Detection")
        
        # Header with status
        col1, col2 = st.columns([1, 5])
        with col1:
            if result.detected:
                st.error("🚨 Threat Detected")
            else:
                st.success("✅ No Threat Detected")
        
        with col2:
            # Confidence meter
            confidence = result.confidence_percent
            if confidence > 70:
                confidence_text = "High"
                confidence_color = "#e74c3c"
            elif confidence > 30:
                confidence_text = "Medium"
                confidence_color = "#f39c12"
            else:
                confidence_text = "Low"
                confidence_color = "#2ecc71"
            
            st.markdown(
                f"<div style='text-align: right;'>"
                f"<span style='font-size: 0.9rem; color: #7f8c8d;'>Confidence: </span>"
                f"<span style='font-weight: 600; color: {confidence_color};'>{confidence}%</span>"
                f"</div>", 
                unsafe_allow_html=True
            )
        
        # Matched rules
        if result.matched_rules:
            with st.expander("🔍 Matched Rules", expanded=True):
                for rule in result.matched_rules:
                    st.markdown(f"- {rule}")
        
        # Evidence
        if result.evidence:
            with st.expander("📊 Evidence", expanded=False):
                st.json(result.evidence, expanded=False)
        
        # Recommended actions
        if result.detected and result.recommended_actions:
            with st.expander("🛡️ Recommended Actions", expanded=True):
                for i, action in enumerate(result.recommended_actions, 1):
                    st.markdown(f"{i}. {action}")

# Main content area based on selected attack type
st.header(f"{attack_type} Detection")

    
    .nav-button {
        white-space: nowrap;
        padding: 0.6rem 1.2rem;
        border-radius: 8px;
        font-size: 0.85rem;
        font-weight: 500;
        color: #475569;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        transition: all 0.2s ease;
        text-decoration: none;
    }
    
    .nav-button:hover {
        background: #f1f5f9;
        color: #1e40af;
        border-color: #bfdbfe;
    }
    
    .nav-button.active {
        background: #1d4ed8;
        color: white;
        border-color: #1d4ed8;
        font-weight: 500;
        box-shadow: 0 1px 3px rgba(29, 78, 216, 0.2);
    }
    
    /* Form Elements */
    .stTextInput>div>div>input, 
    .stTextArea>div>div>textarea,
    .stNumberInput>div>div>input,
    .stSelectbox>div>div>div {
        border: 1px solid #99c2ff !important;
        border-radius: 8px !important;
        background-color: #f5f9ff !important;
    }
    
    /* Buttons */
    .stButton>button {
        background-color: #0066cc !important;
        color: white !important;
        border-radius: 8px !important;
        border: none !important;
        padding: 0.5rem 1rem !important;
    }
    
    .stButton>button:hover {
        background-color: #004d99 !important;
    }
    
    /* Expanders */
    .stExpander {
        border: 1px solid #e6f2ff !important;
        border-radius: 8px !important;
    }
    
    .stExpander .streamlit-expanderHeader {
        background-color: #f5f9ff !important;
    }
    
    /* Modern Headers */
    h1 {
        color: #1e293b !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
        margin: 0 0 1.5rem 0 !important;
        padding-bottom: 0.8rem;
        border-bottom: 1px solid #f1f5f9;
    }
    
    h2 {
        color: #1e40af !important;
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        margin: 2rem 0 1.25rem 0 !important;
    }
    
    h3 {
        color: #1e40af !important;
        font-size: 1.25rem !important;
        font-weight: 500 !important;
        margin: 1.5rem 0 1rem 0 !important;
    }
    
    /* Modern Form Containers */
    .stForm {
        background: white !important;
        padding: 0 !important;
        border-radius: 12px !important;
        margin: 1.5rem 0 !important;
    }
    
    /* Modern Cards and Containers */
    .stContainer, .stAlert, .stExpander {
        background: white !important;
        border-radius: 12px !important;
        padding: 1.5rem !important;
        margin: 1rem 0 !important;
        border: 1px solid #f1f5f9 !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02) !important;
    }
    
    /* Form Rows */
    .stForm > div {
        display: flex;
        flex-wrap: wrap;
        gap: 1.5rem;
        margin-bottom: 1rem;
    }
    
    /* Form Columns */
    .stForm > div > div {
        flex: 1;
        min-width: 280px;
    }
    
    /* Modern Inputs */
    .stTextInput>div>div>input, 
    .stTextArea>div>div>textarea,
    .stNumberInput>div>div>input,
    .stSelectbox>div>div>div {
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        background: white !important;
        padding: 0.625rem 1rem !important;
        font-size: 0.95rem !important;
        transition: all 0.2s ease !important;
    }
    
    .stTextInput>div>div>input:focus, 
    .stTextArea>div>div>textarea:focus,
    .stNumberInput>div>div>input:focus,
    .stSelectbox>div>div>div:focus-within {
        border-color: #1d4ed8 !important;
        box-shadow: 0 0 0 2px rgba(29, 78, 216, 0.15) !important;
        outline: none !important;
    }
    
    /* Modern Buttons */
    .stButton>button {
        background: #1d4ed8 !important;
        color: white !important;
        border-radius: 8px !important;
        border: none !important;
        padding: 0.7rem 1.5rem !important;
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05) !important;
        width: 100%;
        max-width: 200px;
        margin: 1.5rem 0 0.5rem 0 !important;
    }
    
    .stButton>button:hover {
        background: #1e40af !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06) !important;
    }
    </style>
""", unsafe_allow_html=True)

# Form for input parameters
with st.form(key='detection_form'):
    if attack_type == "Ransomware":
        col1, col2 = st.columns(2)
        with col1:
            num_files_modified = st.number_input("Number of Files Modified", min_value=0, value=10)
            entropy_score = st.slider("Entropy Score (0-1)", 0.0, 1.0, 0.5, 0.01)
        with col2:
            time_window_seconds = st.number_input("Time Window (seconds)", min_value=1, value=60)
            ransom_note_found = st.checkbox("Ransom Note Found")
        
        submit_button = st.form_submit_button("Detect Ransomware")
        
        if submit_button:
            result = detector.detect(
                "ransomware",
                num_files_modified=num_files_modified,
                time_window_seconds=time_window_seconds,
                entropy_score=entropy_score,
                ransom_note_found=ransom_note_found
            )
            render_result(result)

    elif attack_type == "Brute Force":
        col1, col2 = st.columns(2)
        with col1:
            failed_attempts = st.number_input("Failed Login Attempts", min_value=0, value=10)
            time_window = st.number_input("Time Window (minutes)", min_value=1, value=5)
        with col2:
            source_ips = st.text_input("Source IPs (comma-separated)", "192.168.1.1, 192.168.1.2, 192.168.1.3")
            account_locked = st.checkbox("Account Locked")
        
        submit_button = st.form_submit_button("Detect Brute Force")
        
        if submit_button:
            result = detector.detect(
                "brute_force",
                failed_attempts=failed_attempts,
                time_window=time_window,
                source_ips=source_ips,
                account_locked=account_locked
            )
            render_result(result)

    elif attack_type == "Phishing":
        email_content = st.text_area("Email Content", "Dear user, please verify your account by clicking the link below...")
        sender_address = st.text_input("Sender Email Address", "support@example.com")
        urls = st.text_input("URLs in Email (comma-separated)", "https://secure-login.example.com, https://www.paypal.com/verify")
        suspicious_keywords = st.text_input("Suspicious Keywords (comma-separated)", "verify, password, urgent")
        
        submit_button = st.form_submit_button("Detect Phishing")
        
        if submit_button:
            result = detector.detect(
                "phishing",
                email_content=email_content,
                sender_address=sender_address,
                urls=urls,
                suspicious_keywords=suspicious_keywords
            )
            render_result(result)

    elif attack_type == "DDoS/Traffic Flood":
        col1, col2 = st.columns(2)
        with col1:
            request_rate = st.number_input("Request Rate (requests/second)", min_value=0, value=500)
            source_ips = st.number_input("Number of Unique Source IPs", min_value=1, value=50)
        with col2:
            traffic_spike = st.number_input("Traffic Spike (% increase)", min_value=0, value=150)
            user_agents = st.number_input("Number of Unique User Agents", min_value=1, value=5)
        
        submit_button = st.form_submit_button("Detect DDoS")
        
        if submit_button:
            result = detector.detect(
                "ddos",
                request_rate=request_rate,
                source_ips=source_ips,
                traffic_spike=traffic_spike,
                user_agents=user_agents
            )
            render_result(result)

    elif attack_type == "Man-in-the-Middle (MITM)":
        protocol = st.radio("Protocol", ["HTTP", "HTTPS"])
        certificate_mismatch = st.checkbox("Certificate Mismatch Detected")
        unencrypted_traffic = st.checkbox("Unencrypted Traffic Detected")
        ssl_errors = st.number_input("SSL/TLS Errors Count", min_value=0, value=0)
        
        submit_button = st.form_submit_button("Detect MITM")
        
        if submit_button:
            result = detector.detect(
                "mitm",
                protocol=protocol,
                certificate_mismatch=certificate_mismatch,
                unencrypted_traffic=unencrypted_traffic,
                ssl_errors=ssl_errors
            )
            render_result(result)

    elif attack_type == "SQL Injection":
        query_string = st.text_area("Database Query", "SELECT * FROM users WHERE username = 'admin' OR '1'='1'")
        suspicious_patterns = st.text_input("Suspicious Patterns (comma-separated)", "OR 1=1, --, ;--, UNION, SELECT")
        error_messages = st.text_area("Database Error Messages (if any)", "")
        query_time = st.number_input("Query Execution Time (ms)", min_value=0, value=100)
        
        submit_button = st.form_submit_button("Detect SQL Injection")
        
        if submit_button:
            result = detector.detect(
                "sql_injection",
                query_string=query_string,
                suspicious_patterns=suspicious_patterns,
                error_messages=error_messages,
                query_time=query_time
            )
            render_result(result)

    elif attack_type == "Cross-Site Scripting (XSS)":
        input_data = st.text_area("Input Data/URL Parameters", "<script>alert('XSS')</script>")
        script_tags = st.number_input("Number of <script> Tags", min_value=0, value=1)
        event_handlers = st.number_input("Number of Event Handlers", min_value=0, value=0)
        url_parameters = st.text_input("URL Parameters", "?name=<script>alert(1)</script>")
        
        submit_button = st.form_submit_button("Detect XSS")
        
        if submit_button:
            result = detector.detect(
                "xss",
                input_data=input_data,
                script_tags=script_tags,
                event_handlers=event_handlers,
                url_parameters=url_parameters
            )
            render_result(result)

    elif attack_type == "Malware":
        file_hash = st.text_input("File Hash", "d41d8cd98f00b204e9800998ecf8427e")
        file_size = st.number_input("File Size (bytes)", min_value=1, value=1024)
        entropy_score = st.slider("Entropy Score (0-1)", 0.0, 1.0, 0.5, 0.01)
        packed = st.checkbox("File is Packed/Compressed")
        
        submit_button = st.form_submit_button("Detect Malware")
        
        if submit_button:
            result = detector.detect(
                "malware",
                file_hash=file_hash,
                file_size=file_size,
                entropy_score=entropy_score,
                packed=packed
            )
            render_result(result)

    elif attack_type == "Insider Threat":
        user_id = st.text_input("User ID", "user123")
        data_volume = st.number_input("Data Volume (MB)", min_value=0.0, value=100.0)
        unusual_time = st.checkbox("Unusual Access Time")
        sensitive_files = st.number_input("Number of Sensitive Files Accessed", min_value=0, value=5)
        
        submit_button = st.form_submit_button("Detect Insider Threat")
        
        if submit_button:
            result = detector.detect(
                "insider_threat",
                user_id=user_id,
                data_volume=data_volume,
                unusual_time=unusual_time,
                sensitive_files=sensitive_files
            )
            render_result(result)

    elif attack_type == "Zero-Day/Novel Anomaly":
        behavior_patterns = st.text_input("Behavior Patterns (comma-separated)", "unusual_process, new_connection, privilege_escalation")
        system_calls = st.number_input("System Calls Count", min_value=0, value=1000)
        memory_usage = st.number_input("Memory Usage (MB)", min_value=0.0, value=500.0)
        anomaly_score = st.slider("Anomaly Score (0-100)", 0, 100, 50)
        
        submit_button = st.form_submit_button("Detect Anomaly")
        
        if submit_button:
            result = detector.detect(
                "zero_day",
                behavior_patterns=behavior_patterns,
                system_calls=system_calls,
                memory_usage=memory_usage,
                anomaly_score=anomaly_score
            )
            render_result(result)

# Footer
st.markdown("""
    <div class='main-content' style='margin-top: 2rem;'>
        <h3>How It Works</h3>
        <div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-top: 1.5rem;'>
            <div style='background: rgba(26, 35, 126, 0.03); padding: 1.5rem; border-radius: 10px; border-left: 4px solid #1a237e; transition: all 0.3s ease;'>
                <h4 style='color: #1a237e; margin-top: 0;'>1. Select Attack Type</h4>
                <p style='color: #424242;'>Choose the type of cyber attack you want to detect from the sidebar.</p>
            </div>
            <div style='background: rgba(26, 35, 126, 0.03); padding: 1.5rem; border-radius: 10px; border-left: 4px solid #3949ab; transition: all 0.3s ease;'>
                <h4 style='color: #1a237e; margin-top: 0;'>2. Enter Details</h4>
                <p style='color: #424242;'>Fill in the required parameters for the selected attack type.</p>
            </div>
            <div style='background: rgba(26, 35, 126, 0.03); padding: 1.5rem; border-radius: 10px; border-left: 4px solid #5c6bc0; transition: all 0.3s ease;'>
                <h4 style='color: #1a237e; margin-top: 0;'>3. Analyze</h4>
                <p style='color: #424242;'>Click the analyze button to check for potential threats.</p>
            </div>
            <div style='background: rgba(26, 35, 126, 0.03); padding: 1.5rem; border-radius: 10px; border-left: 4px solid #9fa8da; transition: all 0.3s ease;'>
                <h4 style='color: #1a237e; margin-top: 0;'>4. Review Results</h4>
                <p style='color: #424242;'>Get detailed analysis, confidence levels, and recommendations.</p>
            </div>
        </div>
        
        <div class='footer-container'>
            <p class='footer-text'>
                CyberShield AI uses advanced algorithms to detect and prevent cyber threats in real-time.
            </p>
        </div>
    </div>
""", unsafe_allow_html=True)
