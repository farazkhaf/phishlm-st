import streamlit as st
import time
from typing import Dict, Any
import analysis
import tldextract
import re

st.set_page_config(
    page_title="PhishLM Analyzer",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    @media (min-width: 769px) {
        [data-testid="stSidebar"] {
            transform: translateX(0) !important;
        }
    }
    
    @media (max-width: 768px) {
        [data-testid="stSidebar"] {
            min-width: 100vw !important;
            max-width: 100vw !important;
            transform: translateX(-100%);
            transition: transform 300ms ease-in-out;
            z-index: 999;
        }
        
        [data-testid="stSidebar"][aria-expanded="true"] {
            transform: translateX(0);
        }
        
        .main .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
        }
        
        .mobile-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            z-index: 998;
            display: none;
        }
        
        [data-testid="stSidebar"][aria-expanded="true"] ~ .mobile-overlay {
            display: block;
        }
    }
    
    [data-testid="stSidebar"] {
        min-width: 350px;
        max-width: 400px;
    }
    
    .phishing-card {
        border-left: 4px solid #dc2626 !important;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 2rem;
    }
    
    .legitimate-card {
        border-left: 4px solid #059669 !important;
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 2rem;
    }
    
    .rationale-card {
        border-left: 4px solid #3b82f6 !important;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.5rem;
    }
    
    .safety-card {
        border-left: 4px solid #f59e0b !important;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.5rem;
    }
    
    .info-card {
        border-left: 4px solid #8b5cf6 !important;
        border-radius: 6px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .metric-card-container {
        border-left: 4px solid #6366f1 !important;
        border-radius: 14px;
        padding: 1.5rem;
        margin-bottom: 1.2rem;
    }
    
    .status-badge-success {
        border: 1px solid #059669 !important;
        border-radius: 16px;
        padding: 4px 12px;
        font-size: 0.875rem;
        font-weight: 500;
    }
    
    .status-badge-warning {
        border: 1px solid #d97706 !important;
        border-radius: 16px;
        padding: 4px 12px;
        font-size: 0.875rem;
        font-weight: 500;
    }
    
    .status-badge-error {
        border: 1px solid #dc2626 !important;
        border-radius: 16px;
        padding: 4px 12px;
        font-size: 0.875rem;
        font-weight: 500;
    }
    
    .status-badge-info {
        border: 1px solid #3b82f6 !important;
        border-radius: 16px;
        padding: 4px 12px;
        font-size: 0.875rem;
        font-weight: 500;
    }
    
    .status-badge-suspicious {
        border: 1px solid #f97316 !important;
        border-radius: 16px;
        padding: 4px 12px;
        font-size: 0.875rem;
        font-weight: 500;
    }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #6366f1, #8b5cf6);
    }
</style>
""", unsafe_allow_html=True)

def sanitize_html(text: str) -> str:
    if not text:
        return ""
    
    text = re.sub(r'<script.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'on\w+="[^"]*"', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+=\'[^\']*\'', '', text, flags=re.IGNORECASE)
    
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    
    text = text.replace('\n', '<br>')
    
    return text

def is_valid_domain(url: str) -> bool:
    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            return False
        domain = extracted.domain
        if not domain.isalnum() and '-' not in domain and '_' not in domain:
            return False
        if not extracted.suffix.replace('.', '').isalpha():
            return False
        return True
    except Exception:
        return False

def display_status_badge(status: str, text: str):
    st.markdown(f'<span class="status-badge-{status}">{text}</span>', unsafe_allow_html=True)

def display_progress_bar(progress_placeholder, current_stage: int, total_stages: int, stage_description: str):
    progress = current_stage / total_stages
    
    progress_placeholder.empty()
    with progress_placeholder.container():
        st.progress(progress)
        st.caption(f"{stage_description}")

def hide_progress_bar(progress_placeholder):
    progress_placeholder.empty()

def display_metric_card(title: str, value: Any, description: str = "", status: str = "info"):
    with st.container():
        st.markdown(f'<div class="metric-card-container">', unsafe_allow_html=True)
        st.markdown(f"**{title}**")
        
        if isinstance(value, (int, float)):
            if isinstance(value, int) and value >= 70:
                value_color = "#dc2626"
            elif isinstance(value, int) and value >= 30:
                value_color = "#d97706"
            else:
                value_color = "#4f46e5"
                
            st.markdown(f'<h3 style="margin: 0; color: {value_color};">{value}</h3>', unsafe_allow_html=True)
        else:
            st.markdown(f'<h3 style="margin: 0; color: #4f46e5;">{value}</h3>', unsafe_allow_html=True)
        
        if description:
            st.caption(description)
        
        if status:
            status_colors = {
                "success": "#059669",
                "warning": "#d97706",
                "error": "#dc2626",
                "info": "#3b82f6",
                "suspicious": "#f97316"
            }
            color = status_colors.get(status, "#3b82f6")
            st.markdown(f'<div style="height: 2px; background: {color}; width: 40px; margin-top: 8px;"></div>', unsafe_allow_html=True)
        
        st.markdown(f'</div>', unsafe_allow_html=True)

def retrieve_content_based_on_option(retrieve_option: str, url: str, progress_placeholder, base_stage: int, total_stages: int):
    if retrieve_option == "none":
        return "No additional data available", "None", base_stage
    
    elif retrieve_option == "pageContent":
        display_progress_bar(progress_placeholder, base_stage, total_stages, "Fetching page content...")
        content = analysis.retrieve_additional_content("pageContent", url)
        return content, "Page Content", base_stage + 1
        
    elif retrieve_option == "searchResults":
        display_progress_bar(progress_placeholder, base_stage, total_stages, "Searching for domain reports...")
        content = analysis.retrieve_additional_content("searchResults", url)
        return content, "Search Results", base_stage + 1
        
    elif retrieve_option == "both":
        display_progress_bar(progress_placeholder, base_stage, total_stages, "Fetching page content...")
        page_content = analysis.retrieve_additional_content("pageContent", url)
        next_stage = base_stage + 1
        display_progress_bar(progress_placeholder, next_stage, total_stages, "Searching for domain reports...")
        search_content = analysis.retrieve_additional_content("searchResults", url)
        
        content = f"PAGE CONTENT:\n{page_content}\n\nSEARCH RESULTS:\n{search_content}"
        return content, "Page Content & Search Results", next_stage + 1
    
    else:
        return "No additional data available", "Unknown", base_stage

def display_final_result(result: Dict[str, Any]):
    st.markdown("### Final Assessment")
    
    if result["prediction"] == "PHISHING":
        st.markdown(
            '<div class="phishing-card">'
            '<h3 style="margin: 0;">PHISHING SITE DETECTED</h3>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<div class="legitimate-card">'
            '<h3 style="margin: 0;">LEGITIMATE SITE</h3>'
            '</div>',
            unsafe_allow_html=True
        )
    
    col1, col2 = st.columns([2, 1], gap="large")
    
    with col1:
        st.markdown("#### Analysis Rationale")
        st.markdown(
            f'<div class="rationale-card">{sanitize_html(result["final_rationale"])}</div>',
            unsafe_allow_html=True
        )
        
        st.markdown("#### Safety Instructions")
        st.markdown(
            f'<div class="safety-card">{sanitize_html(result["safety_instructions"])}</div>',
            unsafe_allow_html=True
        )
    
    with col2:
        st.markdown("#### Analysis Details")
        
        metrics_container = st.container()
        with metrics_container:
            if result.get("llm_risk_score") is not None:
                st.metric(
                    label="Risk Score",
                    value=f"{result['llm_risk_score']}",
                    help="0-100 scale, higher indicates more risk"
                )
            
            if result.get("llm_phishing_prob") is not None:
                prob_percentage = result["llm_phishing_prob"] * 100
                st.metric(
                    label="Phishing Probability",
                    value=f"{prob_percentage:.1f}%",
                    help="Likelihood this is a phishing site"
                )
        
        st.divider()
        
        if result.get("used_retrieval"):
            st.markdown(
                '<div class="info-card">'
                '<p style="margin: 0; font-weight: 500;">Enhanced Analysis</p>'
                '<p style="margin: 0.25rem 0 0 0; font-size: 0.875rem;">Used additional context for higher accuracy</p>'
                '</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div class="info-card">'
                '<p style="margin: 0; font-weight: 500;">URL-Only Analysis</p>'
                '<p style="margin: 0.25rem 0 0 0; font-size: 0.875rem;">Based primarily on URL structure and patterns</p>'
                '</div>',
                unsafe_allow_html=True
            )
        
        if result.get("error"):
            st.markdown(
                f'<div style="padding: 1rem; border-radius: 6px; border-left: 4px solid #dc2626; margin-top: 1rem;">'
                f'<p style="margin: 0; font-size: 0.875rem;"><strong>Note:</strong> {sanitize_html(result["error"])}</p>'
                f'</div>',
                unsafe_allow_html=True
            )

def run_analysis_with_ui(url: str):
    with st.sidebar:
        st.markdown("### Analysis Steps")
        st.divider()
        
        progress_placeholder = st.empty()
        
        display_progress_bar(progress_placeholder, 0, 5, "Validating URL format...")
        
        if not analysis.is_valid_url(url):
            display_metric_card("URL Validation", "FAILED", "Invalid URL format", "error")
            hide_progress_bar(progress_placeholder)
            st.error("Invalid URL format. Please enter a valid URL starting with http:// or https://")
            return None
        
        if not is_valid_domain(url):
            display_metric_card("URL Validation", "INVALID", "Invalid domain structure", "error")
            hide_progress_bar(progress_placeholder)
            st.error("Invalid domain structure detected. Please enter a valid website URL.")
            return None
        
        display_metric_card("URL Validation", "PASSED", "Valid URL format detected", "success")
        time.sleep(0.5)
    
    with st.sidebar:
        display_progress_bar(progress_placeholder, 1, 5, "Running ML analysis...")
        ml_phish_prob, ml_conf, ml_error = analysis.run_ml_analysis(url)
        
        if ml_error:
            display_metric_card("ML Analysis", "FAILED", ml_error, "error")
            hide_progress_bar(progress_placeholder)
            st.error("ML analysis failed. Please try again.")
            return None
        
        ml_status = "warning" if 0.3 <= ml_phish_prob <= 0.7 else ("error" if ml_phish_prob > 0.5 else "success")
        display_metric_card(
            "ML Analysis",
            f"{ml_phish_prob:.1%}",
            f"Phishing probability (URL patterns only)",
            ml_status
        )
        time.sleep(0.5)
    
    with st.sidebar:
        display_progress_bar(progress_placeholder, 2, 5, "Checking if site is live...")
        is_live = analysis.is_page_live(url)
        
        if not is_live:
            display_metric_card("Live Check", "OFFLINE", "Site not accessible", "warning")
            hide_progress_bar(progress_placeholder)
            result = analysis.handle_non_live_url(ml_phish_prob, ml_conf)
            return result
        
        display_metric_card("Live Check", "LIVE", "Site is accessible", "success")
        time.sleep(0.5)
    
    with st.sidebar:
        display_progress_bar(progress_placeholder, 3, 5, "Running initial AI analysis...")
        p1_data, p1_error = analysis.run_initial_llm_analysis(url, ml_phish_prob)
        
        if p1_error:
            display_metric_card("Initial AI", "FAILED", p1_error, "error")
            hide_progress_bar(progress_placeholder)
            result = analysis.initialize_result_template()
            result.update({
                "prediction": "PHISHING" if ml_phish_prob > 0.5 else "LEGITIMATE",
                "overall_confidence": ml_conf,
                "ml_phishing_prob": ml_phish_prob,
                "llm_risk_score": round(ml_phish_prob * 100),
                "final_rationale": "LLM analysis failed; falling back to ML analysis results.",
                "safety_instructions": "Exercise caution. Analysis incomplete due to technical error.",
                "used_retrieval": False,
                "error": p1_error
            })
            return result
        
        initial_risk_score = p1_data["risk_score"]
        certainty = p1_data["certainty"]
        retrieve = p1_data["retrieve"]
        initial_rationale = p1_data["initial_rationale"]
        
        risk_status = "suspicious" if initial_risk_score >= 70 else ("warning" if initial_risk_score >= 30 else "success")
        display_metric_card(
            "Initial AI Risk",
            f"{initial_risk_score}/100",
            "Initial risk assessment",
            risk_status
        )
        
        if retrieve != "none":
            if retrieve == "pageContent":
                next_step_text = "Retrieve Page Content"
            elif retrieve == "searchResults":
                next_step_text = "Retrieve Search Results"
            elif retrieve == "both":
                next_step_text = "Retrieve Both"
            else:
                next_step_text = "Unknown"
                
            display_metric_card("Next Step", next_step_text, "Enhanced analysis needed", "info")
        else:
            display_metric_card("Next Step", "Direct to Safety", "High certainty achieved", "success")
        
        time.sleep(0.5)
    
    if retrieve == "none":
        total_stages = 5
        current_stage = 4
        
        with st.sidebar:
            display_progress_bar(progress_placeholder, current_stage, total_stages, "Generating safety guidance...")
            p3_result, p3_error = analysis.run_safety_only_analysis(
                url, ml_phish_prob, initial_risk_score, initial_rationale
            )
            final_risk_score = p3_result["final_risk_score"]
            final_rationale = p3_result["final_rationale"]
            safety_instructions = p3_result["safety_instructions"]
            used_retrieval = False
            
            if p3_error:
                display_metric_card("Safety Analysis", "PARTIAL", p3_error, "warning")
            else:
                display_metric_card("Safety Analysis", "COMPLETE", "Guidance generated", "success")
    else:
        if retrieve == "both":
            total_stages = 7
        else:
            total_stages = 6
        
        current_stage = 4
        with st.sidebar:
            additional_content, retrieval_text, next_stage = retrieve_content_based_on_option(
                retrieve, url, progress_placeholder, current_stage, total_stages
            )
            
            if "No additional data available." == additional_content:
                display_metric_card("Retrieval", "NO DATA", "Could not retrieve additional context", "warning")
            else:
                display_metric_card("Retrieval", "SUCCESS", f"Retrieved {retrieval_text}", "success")
            
            time.sleep(0.5)
            
            display_progress_bar(progress_placeholder, next_stage, total_stages, "Running enhanced AI analysis...")
            p2_result, p2_error = analysis.run_context_refined_analysis(
                url, ml_phish_prob, initial_risk_score, initial_rationale, additional_content
            )
            
            final_risk_score = p2_result["final_risk_score"]
            final_rationale = p2_result["final_rationale"]
            safety_instructions = p2_result["safety_instructions"]
            used_retrieval = True
            
            if p2_error:
                display_metric_card("Enhanced AI", "PARTIAL", p2_error, "warning")
            else:
                display_metric_card("Enhanced AI", "COMPLETE", "Analysis complete", "success")
    
    hide_progress_bar(progress_placeholder)

    result = analysis.compute_final_results(
        ml_phish_prob=ml_phish_prob,
        ml_conf=ml_conf,
        final_risk_score=final_risk_score,
        final_rationale=final_rationale,
        safety_instructions=safety_instructions,
        used_retrieval=used_retrieval
    )
    
    return result

def main():
    if 'request_count' not in st.session_state:
        st.session_state.request_count = 0
    if 'last_reset_time' not in st.session_state:
        st.session_state.last_reset_time = time.time()
    
    if time.time() - st.session_state.last_reset_time > 1800:
        st.session_state.request_count = 0
        st.session_state.last_reset_time = time.time()
    
    MAX_REQUESTS = 10
    
    limit_reached = st.session_state.request_count >= MAX_REQUESTS
    
    st.markdown("# PhishLM Security Analyzer")
    st.markdown("Advanced AI-powered phishing detection using URL analysis, ML patterns, and contextual intelligence")
    st.divider()
    
    url_col, btn_col = st.columns([3, 1])
    
    with url_col:
        url = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter a complete URL starting with http:// or https://",
            label_visibility="collapsed",
            disabled=limit_reached
        )
    
    with btn_col:
        analyze_button = st.button(
            "Analyze", 
            type="primary", 
            use_container_width=True,
            disabled=limit_reached
        )
        
        if limit_reached:
            st.caption(f"Limit: {st.session_state.request_count}/{MAX_REQUESTS}")
    
    st.divider()
    
    with st.expander("How it works", expanded=False):
        st.markdown("""
        1. **URL Validation** - Checks if the URL format and domain structure are valid
        2. **ML Analysis** - Uses machine learning to detect phishing patterns in URL structure
        3. **Live Check** - Verifies if the website is accessible
        4. **Initial AI Analysis** - AI evaluates phishing risk based on URL alone
        5. **Enhanced Analysis** (if needed) - Can retrieve page content, search results, or both for more accurate assessment
        6. **Final Assessment** - Combines all analysis for comprehensive security evaluation
        """)
    
    if analyze_button and url:
        if limit_reached:
            st.warning(f"Rate limit reached. You've used {st.session_state.request_count} out of {MAX_REQUESTS} analyses. Please try again in an hour.")
            return
        
        st.session_state.request_count += 1
        
        if not url.startswith(('http://', 'https://')):
            st.warning("Please enter a complete URL starting with http:// or https://")
            return
        
        with st.spinner("Starting analysis..."):
            result = run_analysis_with_ui(url)
        
        if result:
            display_final_result(result)
    
    elif analyze_button and not url:
        st.warning("Please enter a URL to analyze")
    
    st.divider()
    st.caption("PhishLM Analyzer • Professional Security Assessment Tool")
    st.caption("Always exercise caution when visiting unfamiliar websites")

if __name__ == "__main__":
    main()
