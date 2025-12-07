
import streamlit as st
import time
from typing import Dict, Any
import analysis
import tldextract
import markdown

st.set_page_config(
    page_title="PhishLM Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    [data-testid="stSidebar"] {
        min-width: 400px;
        max-width: 450px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #6366f1, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.8rem;
        letter-spacing: -0.02em;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #6b7280;
        margin-bottom: 2rem;
        line-height: 1.6;
    }
    .final-card {
        background: linear-gradient(135deg, #f0f9ff, #fdf2f8);
        border-radius: 16px;
        padding: 2.5rem;
        border: 1px solid #e0e7ff;
        box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.1);
        backdrop-filter: blur(10px);
    }
    .status-badge {
        display: inline-block;
        padding: 0.3rem 0.9rem;
        border-radius: 24px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.025em;
    }
    .metric-value {
        font-size: 1.2rem;
        font-weight: 700;
        color: #4f46e5;
        line-height: 1.4;
    }
    .success {
        color: #059669;
        background: linear-gradient(135deg, #d1fae5, #a7f3d0);
        border: 1px solid #a7f3d0;
    }
    .warning {
        color: #d97706;
        background: linear-gradient(135deg, #fef3c7, #fde68a);
        border: 1px solid #fde68a;
    }
    .error {
        color: #dc2626;
        background: linear-gradient(135deg, #fee2e2, #fecaca);
        border: 1px solid #fecaca;
    }
    .info {
        color: #3b82f6;
        background: linear-gradient(135deg, #dbeafe, #bfdbfe);
        border: 1px solid #bfdbfe;
    }
    .suspicious {
        color: #f97316;
        background: linear-gradient(135deg, #ffedd5, #fed7aa);
        border: 1px solid #fed7aa;
    }
</style>
""", unsafe_allow_html=True)

def is_valid_domain(url: str) -> bool:
    """Check if the URL has a valid domain structure using tldextract."""
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
    """Display a status badge with appropriate color."""
    color_class = {
        "success": "safe",
        "warning": "warning",
        "error": "risk",
        "info": "info",
        "suspicious": "suspicious"
    }.get(status, "info")
    
    st.markdown(f'<span class="status-badge {color_class}">{text}</span>', unsafe_allow_html=True)

def display_progress_bar(progress_placeholder, current_stage: int, total_stages: int, stage_description: str):
    """Display progress bar with current stage description."""
    progress = current_stage / total_stages

    progress_placeholder.empty()
    with progress_placeholder.container():
        st.progress(progress)
        st.markdown(
            f'<p style="text-align: center; margin-top: 0.5rem; color: #6b7280; font-weight: 500;"><strong>{stage_description}</strong></p>',
            unsafe_allow_html=True
        )

def hide_progress_bar(progress_placeholder):
    """Clear the progress bar placeholder."""
    progress_placeholder.empty()

def display_metric_card(title: str, value: Any, description: str = "", status: str = "info"):
    """Display a metric card in the sidebar."""
    badge_html = ""
    if status:
        color_class = {
            "success": "success",
            "warning": "warning",
            "error": "error",
            "info": "info",
            "suspicious": "suspicious"
        }.get(status, "info")
        badge_html = f'<span class="status-badge {color_class}">{status.upper()}</span>'
    
    html = f"""
    <div style="
        background: linear-gradient(135deg, #f8fafc, #f1f5f9);
        border-radius: 14px;
        padding: 1.5rem;
        margin-bottom: 1.2rem;
        border-left: 4px solid #6366f1;
        box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.1);
        backdrop-filter: blur(10px);
    ">
        <h4 style="margin-top: 0; margin-bottom: 0.6rem; color: #374151; font-weight: 600; font-size: 1.1rem;">{title}</h4>
        <p class="metric-value">{value}</p>
    """
    
    if description:
        html += f'<p style="color: #6b7280; font-size: 0.9rem; margin-bottom: 0.6rem; line-height: 1.5;">{description}</p>'
    
    if badge_html:
        html += f'<p style="margin-bottom: 0;">{badge_html}</p>'
    
    html += '</div>'
    
    st.markdown(html, unsafe_allow_html=True)

def retrieve_content_based_on_option(retrieve_option: str, url: str, progress_placeholder, base_stage: int, total_stages: int):
    """Handle different retrieval options and return content with appropriate progress tracking."""
    
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
    """Display the final analysis result."""
    col1, col2 = st.columns([2, 1])
    
    with col1:
        html = """
        <div style="
            background: linear-gradient(135deg, #f0f9ff, #fdf2f8);
            border-radius: 16px;
            padding: 2.5rem;
            border: 1px solid #e0e7ff;
            box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.1);
            backdrop-filter: blur(10px);
        ">
        """
        
        # Prediction
        if result["prediction"] == "PHISHING":
            html += '<div style="color: #dc2626; font-size: 1.6rem; font-weight: 700; margin-bottom: 1.2rem; text-align: center; background: linear-gradient(135deg, #fee2e2, #fecaca); padding: 1rem; border-radius: 12px; border: 1px solid #fecaca;">PHISHING SITE DETECTED</div>'
        else:
            html += '<div style="color: #059669; font-size: 1.6rem; font-weight: 700; margin-bottom: 1.2rem; text-align: center; background: linear-gradient(135deg, #d1fae5, #a7f3d0); padding: 1rem; border-radius: 12px; border: 1px solid #a7f3d0;">LEGITIMATE SITE</div>'
        
        # Final Rationale
        html += f"""
        <div style="margin-bottom: 1.8rem;">
            <h3 style="margin-bottom: 0.6rem; color: #374151; font-weight: 600; font-size: 1.3rem;">Analysis Rationale</h3>
            <div style="
                background: linear-gradient(135deg, #e0f2fe, #bae6fd);
                padding: 1.2rem;
                border-radius: 12px;
                border-left: 4px solid #3b82f6;
                box-shadow: 0 2px 4px -1px rgba(59, 130, 246, 0.1);
            ">
                {markdown.markdown(result["final_rationale"])}
            </div>
        </div>
        """
        
        # Safety Instructions
        html += f"""
        <div>
            <h3 style="margin-bottom: 0.6rem; color: #374151; font-weight: 600; font-size: 1.3rem;">Safety Instructions</h3>
            <div style="
                background: linear-gradient(135deg, #fffbeb, #fef3c7);
                padding: 1.2rem;
                border-radius: 12px;
                border-left: 4px solid #f59e0b;
                color: #92400e;
                box-shadow: 0 2px 4px -1px rgba(245, 158, 11, 0.1);
            ">
                {markdown.markdown(result["safety_instructions"])}
            </div>
        </div>
        """
        
        html += '</div>'
        st.markdown(html, unsafe_allow_html=True)
    
    with col2:
        st.markdown("### Analysis Details")
        
        if result.get("llm_risk_score") is not None:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #f9fafb, #f3f4f6); padding: 1.2rem; border-radius: 12px; margin-bottom: 1.2rem; box-shadow: 0 4px 6px -1px rgba(107, 114, 128, 0.1);">
                <p style="color: #374151; font-size: 0.95rem; margin-bottom: 0.6rem;"><strong>LLM Risk Score:</strong></p>
                <p style="color: #4f46e5; font-size: 1.6rem; font-weight: 700; margin: 0;">{result["llm_risk_score"]}/100</p>
            </div>
            """, unsafe_allow_html=True)
        
        if result.get("llm_phishing_prob") is not None:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #f9fafb, #f3f4f6); padding: 1.2rem; border-radius: 12px; margin-bottom: 1.2rem; box-shadow: 0 4px 6px -1px rgba(107, 114, 128, 0.1);">
                <p style="color: #374151; font-size: 0.95rem; margin-bottom: 0.6rem;"><strong>LLM Phishing Probability:</strong></p>
                <p style="color: #4f46e5; font-size: 1.6rem; font-weight: 700; margin: 0;">{result["llm_phishing_prob"]:.1%}</p>
            </div>
            """, unsafe_allow_html=True)
        
        if result.get("used_retrieval"):
            display_status_badge("info", "ENHANCED ANALYSIS")
            st.markdown("""
            <div style="background: linear-gradient(135deg, #e0f2fe, #bae6fd); padding: 1.2rem; border-radius: 12px; margin-top: 1.2rem; box-shadow: 0 2px 4px -1px rgba(59, 130, 246, 0.1);">
                <p style="color: #1e40af; font-size: 0.95rem; margin: 0;">
                    <strong>Enhanced Analysis:</strong> This assessment used additional context from page content or search results for higher accuracy.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            display_status_badge("info", "URL-ONLY ANALYSIS")
            st.markdown("""
            <div style="background: linear-gradient(135deg, #e0f2fe, #bae6fd); padding: 1.2rem; border-radius: 12px; margin-top: 1.2rem; box-shadow: 0 2px 4px -1px rgba(59, 130, 246, 0.1);">
                <p style="color: #1e40af; font-size: 0.95rem; margin: 0;">
                    <strong>URL Analysis:</strong> This assessment was based primarily on URL structure and patterns.
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        if result.get("error"):
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #fef2f2, #fecaca); padding: 1.2rem; border-radius: 12px; margin-top: 1.2rem; box-shadow: 0 2px 4px -1px rgba(220, 38, 38, 0.1);">
                <p style="color: #991b1b; font-size: 0.95rem; margin: 0;">
                    <strong>Note:</strong> {result['error']}
                </p>
            </div>
            """, unsafe_allow_html=True)

def run_analysis_with_ui(url: str):
    """Run the analysis pipeline with UI updates."""
    
    # Initialize sidebar for intermediate results
    with st.sidebar:
        st.markdown("### Analysis Steps")
        st.markdown("---")
        
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
    
    #  2: Live Check
    with st.sidebar:
        display_progress_bar(progress_placeholder, 2, 5, "Checking if site is live...")
        is_live = analysis.is_page_live(url)
        
        if not is_live:
            display_metric_card("Live Check", "OFFLINE", "Site not accessible", "warning")
            hide_progress_bar(progress_placeholder)
            # Use non-live handler
            result = analysis.handle_non_live_url(ml_phish_prob, ml_conf)
            return result
        
        display_metric_card("Live Check", "LIVE", "Site is accessible", "success")
        time.sleep(0.5)
    
    #  3: Initial LLM Analysis
    with st.sidebar:
        display_progress_bar(progress_placeholder, 3, 5, "Running initial AI analysis...")
        p1_data, p1_error = analysis.run_initial_llm_analysis(url, ml_phish_prob)
        
        if p1_error:
            display_metric_card("Initial AI", "FAILED", p1_error, "error")
            hide_progress_bar(progress_placeholder)
            # Fallback to ML result
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
            initial_rationale,
            risk_status
        )
        
        if retrieve != "none":
            #  display text for the next step
            if retrieve == "pageContent":
                next_step_text = "Retrieve Page Content"
            elif retrieve == "searchResults":
                next_step_text = "Retrieve Search Results"
            elif retrieve == "both":
                next_step_text = "Retrieve Both Page Content & Search"
            else:
                next_step_text = "Unknown Retrieval Type"
                
            display_metric_card("Next Step", next_step_text, "Enhanced analysis needed", "info")
        else:
            display_metric_card("Next Step", "Direct to Safety", "High certainty achieved", "success")
        
        time.sleep(0.5)
    
    # 4: Branch based on retrieval
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
            total_stages = 7  # URL, ML, Live, Initial AI, Page Content, Search Results, Enhanced AI
        else:
            total_stages = 6  # URL, ML, Live, Initial AI, Retrieval, Enhanced AI
        
        current_stage = 4
        with st.sidebar:
            additional_content, retrieval_text, next_stage = retrieve_content_based_on_option(
                retrieve, url, progress_placeholder, current_stage, total_stages
            )
            print("---------------------",additional_content)
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
    """Main Streamlit application."""
    
    # Header
    st.markdown('<h1 class="main-header">PhishLLM Security Analyzer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Advanced AI-powered phishing detection using URL analysis, ML patterns, and contextual intelligence</p>', unsafe_allow_html=True)
    
    # URL Input
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com  ",
            help="Enter a complete URL starting with http:// or https://"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_button = st.button("Analyze URL", type="primary", use_container_width=True)
    
    st.markdown("---")
    
    # Information section
    with st.expander("How it works:"):
        st.markdown("""
        1. **URL Validation** - Checks if the URL format and domain structure are valid
        2. **ML Analysis** - Uses machine learning to detect phishing patterns in URL structure
        3. **Live Check** - Verifies if the website is accessible
        4. **Initial AI Analysis** - AI evaluates phishing risk based on URL alone
        5. **Enhanced Analysis** (if needed) - Can retrieve page content, search results, or both for more accurate assessment
        6. **Final Assessment** - Combines all analysis for comprehensive security evaluation
        """)
    
    if analyze_button and url:
        if not url.startswith(('http://', 'https://')):
            st.warning("Please enter a complete URL starting with http:// or https://")
            return
        
        results_placeholder = st.empty()
        
        with results_placeholder.container():
            st.info("Starting analysis... Please wait.")
        
        result = run_analysis_with_ui(url)
        
        results_placeholder.empty()
        
        if result:
            display_final_result(result)
    
    elif analyze_button and not url:
        st.warning("Please enter a URL to analyze")
    
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #6b7280; font-size: 0.9rem; margin-top: 3rem;">
        <p>PhishLLM Analyzer • Professional Security Assessment Tool</p>
        <p>Always exercise caution when visiting unfamiliar websites</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
