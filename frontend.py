import streamlit as st
import time
from typing import Dict, Any
import analysis
import tldextract
import re

# Page config
st.set_page_config(
    page_title="PhishLM security analyzer",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# Single global styles block
st.markdown("""
<style>
#MainMenu {visibility: hidden;}
header {visibility: hidden;}
footer {visibility: hidden;}

:root {
  --muted:       #6b7280;
  --border:      rgba(0, 0, 0, 0.12);
  --bg-soft:     rgba(220, 225, 230, 0.25);
  --accent:      #3d99f5;
  --accent-2:    #7c3aed;
  --safe:        #10b981;
  --risk:        #ef4444;
}


.section {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-soft);
  padding: 1rem;
  margin-bottom: 1rem;
}

[data-testid="stProgress"] > div > div > div > div {
  background: linear-gradient(90deg, var(--accent), var(--accent-2));
}
h1 {
        color: var(--accent) !important;
    }
/* Primary button styles */
button[kind="primary"] span {
  font-weight: 900 !important;
}
button[kind="primary"] {
  background-color: var(--accent) !important;
    border: 0px;
}

/* Sticky Left Column (Desktop) */
@media (min-width: 900px) {
  [data-testid="column"]:first-child > div {
    position: sticky;
    top: 1rem;
    max-height: calc(100vh - 2rem);
    overflow: auto;
    padding-right: 0.25rem;
  }
}
            
                
  div[data-baseweb="base-input"] {
        border-color: var(--accent) !important;
    }

    
            
            

h3, h4 { margin-top: 0.25rem; margin-bottom: 0.5rem; }
</style>
""", unsafe_allow_html=True)


# ---------------------------
# Utilities
# ---------------------------

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

# Progress/state helpers
def init_session_state():
    defaults = {
        'request_count': 0,
        'last_reset_time': time.time(),
        'progress_stage': 0,
        'total_stages': 5,
        'metrics': [],
        'progress_desc': "",
        'final_result': None,
        'sidebar_init': False
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

def set_progress(stage: int, total: int, desc: str):
    st.session_state.progress_stage = stage
    st.session_state.total_stages = total
    st.session_state.progress_desc = desc

def complete_progress(desc: str = "Completed"):
    st.session_state.progress_stage = st.session_state.total_stages
    st.session_state.progress_desc = desc

def add_metric(title: str, value: Any, description: str = ""):
    st.session_state.metrics.append((title, value, description))

# ---------------------------
# Sidebar UI Updater
# ---------------------------
def update_sidebar_ui(placeholder):
    """
    Refreshes the sidebar UI using a Streamlit placeholder.
    This ensures the previous content is completely replaced (cleared) 
    before writing the new state.
    """
    with placeholder.container():
        st.markdown("### Analysis progress")
        
        # Safe division for progress bar
        curr = st.session_state.progress_stage
        total = max(st.session_state.total_stages, 1)
        prog_val = min(curr / total, 1.0)
        
        st.progress(prog_val)
        st.caption(st.session_state.progress_desc or "Ready to analyze")

        st.divider()

        st.markdown("### Analysis metrics")
        # Inject CSS once
        st.markdown(
            """
            <style>
            .metric-card {
                border-left: solid var(--accent) ; 
                padding: 0.5em 1em;
                margin-bottom: 0.75em;
                border-radius: 3px;
            }
            .metric-title {
                font-weight: bold;
            }
            .metric-value {
                margin-left: 0.5em;
            }
            </style>
            """,
            unsafe_allow_html=True
        )

        if st.session_state.metrics:
            for title, value, desc in st.session_state.metrics:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-title">{title}</div>
                        <div class="metric-value">● {value}</div>
                        <div class="metric-desc"><em>{desc or ""}</em></div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.caption("No metrics to display yet.")


# ---------------------------
# Analysis flow
# ---------------------------

def retrieve_content_based_on_option(retrieve_option: str, url: str, base_stage: int, total_stages: int, sidebar_placeholder):
    if retrieve_option == "none":
        set_progress(base_stage, total_stages, "No additional retrieval requested")
        update_sidebar_ui(sidebar_placeholder)
        return "No additional data available", "None", base_stage

    elif retrieve_option == "pageContent":
        set_progress(base_stage, total_stages, "Fetching page content…")
        update_sidebar_ui(sidebar_placeholder)
        content = analysis.retrieve_additional_content("pageContent", url)
        return content, "Page content", base_stage + 1

    elif retrieve_option == "searchResults":
        set_progress(base_stage, total_stages, "Searching for domain reports…")
        update_sidebar_ui(sidebar_placeholder)
        content = analysis.retrieve_additional_content("searchResults", url)
        return content, "Search results", base_stage + 1

    elif retrieve_option == "both":
        set_progress(base_stage, total_stages, "Fetching page content…")
        update_sidebar_ui(sidebar_placeholder)
        page_content = analysis.retrieve_additional_content("pageContent", url)
        
        next_stage = base_stage + 1
        set_progress(next_stage, total_stages, "Searching for domain reports…")
        update_sidebar_ui(sidebar_placeholder)
        search_content = analysis.retrieve_additional_content("searchResults", url)
        
        content = f"PAGE CONTENT:\n{page_content}\n\nSEARCH RESULTS:\n{search_content}"
        return content, "Page content & search results", next_stage + 1

    else:
        set_progress(base_stage, total_stages, "Unknown retrieval option")
        update_sidebar_ui(sidebar_placeholder)
        return "No additional data available", "Unknown", base_stage


def run_analysis_with_ui(url: str, sidebar_placeholder) -> Dict[str, Any] | None:
    """
    Runs the analysis pipeline while updating the sidebar_placeholder in real-time.
    """
    
    # Stage 0: Validate URL
    set_progress(0, 5, "Validating URL format…")
    update_sidebar_ui(sidebar_placeholder)

    if not analysis.is_valid_url(url):
        add_metric("Url validation", "Invalid", "Invalid URL format")
        complete_progress("Completed with validation error")
        update_sidebar_ui(sidebar_placeholder)
        st.warning("Invalid URL format. Please enter a valid URL starting with http:// or https://")
        return None

    if not is_valid_domain(url):
        add_metric("Url validation", "Invalid", "Invalid domain structure")
        complete_progress("Completed with validation error")
        update_sidebar_ui(sidebar_placeholder)
        st.warning("Invalid domain structure detected. Please enter a valid website URL.")
        return None

    add_metric("Url validation", "Passed", "Valid URL format detected")
    update_sidebar_ui(sidebar_placeholder)
    time.sleep(0.3)

    # Stage 1: ML analysis
    set_progress(1, st.session_state.total_stages, "Running ML analysis…")
    update_sidebar_ui(sidebar_placeholder)
    ml_phish_prob, ml_conf, ml_error = analysis.run_ml_analysis(url)

    if ml_error:
        add_metric("Ml analysis", "Failed", ml_error)
        complete_progress("Completed with ML error")
        update_sidebar_ui(sidebar_placeholder)
        st.warning("ML analysis failed. Please try again.")
        return None

    add_metric("Ml analysis", f"{ml_phish_prob:.1%}", "Phishing probability (URL patterns only)")
    update_sidebar_ui(sidebar_placeholder)
    time.sleep(0.3)

    # Stage 2: Live check
    set_progress(2, st.session_state.total_stages, "Checking if site is live…")
    update_sidebar_ui(sidebar_placeholder)
    is_live = analysis.is_page_live(url)

    if not is_live:
        add_metric("Live check", "Offline", "Site not live or accessible")
        result = analysis.handle_non_live_url(ml_phish_prob, ml_conf)
        complete_progress("Completed (site offline)")
        update_sidebar_ui(sidebar_placeholder)
        return result

    add_metric("Live check", "Live", "Site is accessible")
    update_sidebar_ui(sidebar_placeholder)
    time.sleep(0.3)

    # Stage 3: Initial LLM analysis
    set_progress(3, st.session_state.total_stages, "Running initial AI analysis…")
    update_sidebar_ui(sidebar_placeholder)
    p1_data, p1_error = analysis.run_initial_llm_analysis(url, ml_phish_prob)

    if p1_error:
        add_metric("Initial AI", "Failed", p1_error)
        result = analysis.initialize_result_template()
        result.update({
            "prediction": "phishing" if ml_phish_prob > 0.5 else "legitimate",
            "overall_confidence": ml_conf,
            "ml_phishing_prob": ml_phish_prob,
            "llm_risk_score": round(ml_phish_prob * 100),
            "final_rationale": "AI analysis failed; falling back to ML analysis results.",
            "safety_instructions": "Exercise caution. Analysis incomplete due to technical error.",
            "used_retrieval": False,
            "error": p1_error
        })
        complete_progress("Completed (AI fallback)")
        update_sidebar_ui(sidebar_placeholder)
        return result

    initial_risk_score = p1_data["risk_score"]
    certainty = p1_data["certainty"]
    retrieve = p1_data["retrieve"]
    initial_rationale = p1_data["initial_rationale"]

    add_metric("Initial AI risk", f"{initial_risk_score}/100", "Initial risk assessment")
    
    if retrieve != "none":
        next_step_text = f"Retrieve {retrieve}"
        add_metric("Next step", next_step_text, "Enhanced analysis needed")
    else:
        add_metric("Next step", "Direct to safety", "High certainty achieved")
    
    update_sidebar_ui(sidebar_placeholder)
    time.sleep(0.3)

    # Stage 4+: Retrieval and enhanced AI or Safety-only path
    if retrieve == "none":
        total_stages = 5
        current_stage = 4
        set_progress(current_stage, total_stages, "Generating safety guidance…")
        update_sidebar_ui(sidebar_placeholder)
        
        p3_result, p3_error = analysis.run_safety_only_analysis(
            url, ml_phish_prob, initial_risk_score, initial_rationale
        )
        final_risk_score = p3_result["final_risk_score"]
        final_rationale = p3_result["final_rationale"]
        safety_instructions = p3_result["safety_instructions"]
        used_retrieval = False

        if p3_error:
            add_metric("Safety analysis", "Partial", p3_error)
        else:
            add_metric("Safety analysis", "Complete", "Guidance generated")

    else:
        total_stages = 7 if retrieve == "both" else 6
        current_stage = 4

        additional_content, retrieval_text, next_stage = retrieve_content_based_on_option(
            retrieve, url, current_stage, total_stages, sidebar_placeholder
        )

        if "No additional data available." == additional_content:
            add_metric("Retrieval", "No data", "Could not retrieve additional context")
        else:
            add_metric("Retrieval", "Success", f"Retrieved {retrieval_text}")

        update_sidebar_ui(sidebar_placeholder)
        time.sleep(0.3)

        set_progress(next_stage, total_stages, "Running enhanced AI analysis…")
        update_sidebar_ui(sidebar_placeholder)
        
        p2_result, p2_error = analysis.run_context_refined_analysis(
            url, ml_phish_prob, initial_risk_score, initial_rationale, additional_content
        )

        final_risk_score = p2_result["final_risk_score"]
        final_rationale = p2_result["final_rationale"]
        safety_instructions = p2_result["safety_instructions"]
        used_retrieval = True

        if p2_error:
            add_metric("Enhanced AI", "Partial", p2_error)
        else:
            add_metric("Enhanced AI", "Complete", "Analysis complete")

    # Final combine
    result = analysis.compute_final_results(
        ml_phish_prob=ml_phish_prob,
        ml_conf=ml_conf,
        final_risk_score=final_risk_score,
        final_rationale=final_rationale,
        safety_instructions=safety_instructions,
        used_retrieval=used_retrieval
    )

    complete_progress("Completed")
    update_sidebar_ui(sidebar_placeholder)
    return result

def risk_score_card(score: int):
    if score >= 70:
        color = "#F76D4E"   # high risk
    elif score >= 40:
        color = "#F5CF37"   # medium risk
    else:
        color = "#48C65D"   # low risk

    st.markdown(
        f"""
            <h4 style="margin:0;">Risk Score</h4>
            <p style="margin-left: 15px; font-size:3em; font-weight:bold; color:{color};">
                {score}/100
            </p>
            <small style="color:gray;">0 = Safe, 100 = High Risk</small>

        """,
        unsafe_allow_html=True
    )


def display_final_result(result: Dict[str, Any]):
    st.markdown("### Final assessment")

    # Determine score
    score = result.get("llm_risk_score", result.get("final_risk_score", None))
    if score is None:
        score = round(result.get("ml_phishing_prob", 0) * 100)

    # 1. RISK SCORE
    risk_score_card(score)

    st.divider()

    # 2. RATIONALE
    st.markdown("#### Analysis rationale")
    st.markdown(result.get("final_rationale", "No rationale provided."))

    # 3. SAFETY INSTRUCTIONS
    st.markdown("#### Safety instructions")
    st.markdown(result.get("safety_instructions", "No safety instructions provided."))

    # 4. Technical Details (Always visible / Not expandable)
    st.divider()
    st.markdown("#### Technical details")
    
    if result.get("llm_phishing_prob") is not None:
        prob_percentage = result["llm_phishing_prob"] * 100
        st.write(f"**Phishing probability:** {prob_percentage:.1f}%")
    
    if result.get("used_retrieval"):
        st.write("**Analysis Type:** Enhanced (Content Retrieval)")
    else:
        st.write("**Analysis Type:** Standard (URL Pattern)")
        
    if result.get("error"):
        st.write(f"**System Note:** {result['error']}")


# ---------------------------
# App main
# ---------------------------

def main():
    init_session_state()

    # Reset rate limit every 30 minutes
    if time.time() - st.session_state.last_reset_time > 1800:
        st.session_state.request_count = 0
        st.session_state.last_reset_time = time.time()

    MAX_REQUESTS = 10
    limit_reached = st.session_state.request_count >= MAX_REQUESTS

    # Header
    st.markdown("# PhishLM security analyzer")
    st.markdown("Advanced AI-powered phishing detection using URL analysis, ML patterns, and contextual intelligence")
    st.divider()

    # Input Section
    left_input, right_btn = st.columns([3, 1])
    with left_input:
        url = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter a complete URL starting with http:// or https://",
            label_visibility="collapsed",
            disabled=limit_reached
        )
    with right_btn:
        analyze_button = st.button(
            "Analyze",
            type="primary",
            use_container_width=True,
            disabled=limit_reached
        )
        if limit_reached:
            st.caption(f"Limit: {st.session_state.request_count}/{MAX_REQUESTS}")

    st.divider()

    # How it works (Expandable)
    with st.expander("How it works", expanded=False):
        st.markdown("""
        **URL Validation** — Checks if the URL format and domain structure are valid
        
        **ML Analysis** — Uses machine learning to detect phishing patterns in URL structure
        
        **Live Check** — Verifies if the website is accessible
        
        **Initial AI Analysis** — AI evaluates phishing risk based on URL
        
        **Enhanced Analysis** (if needed) — Can retrieve page content (including forms, external refs, etc), search results on web, for more accurate assessment
        
        **Final Assessment** — Combines all analysis for comprehensive security evaluation
        """)

    # Main Layout Columns
    # Left: Progress/Metrics (Sidebar) | Right: Results
    left_col, right_col = st.columns([3, 7])

    # Create a placeholder in the left column for updates. 
    # This allows us to clear just this section easily.
    sidebar_placeholder = left_col.empty()
    
    # Initialize sidebar in the placeholder
    update_sidebar_ui(sidebar_placeholder)

    # Right column interaction
    with right_col:
        if analyze_button and url:
            if limit_reached:
                st.warning("Rate limit reached.")
            else:
                st.session_state.request_count += 1
                
                # Reset metrics for new run
                st.session_state.metrics = []
                st.session_state.progress_stage = 0
                st.session_state.progress_desc = "Starting..."

                if not url.startswith(('http://', 'https://')):
                    st.warning("Please enter a complete URL starting with http:// or https://")
                else:
                    with st.spinner("Starting analysis..."):
                        # PASS the placeholder, NOT the whole column
                        result = run_analysis_with_ui(url, sidebar_placeholder)

                    if result:
                        display_final_result(result)

        elif analyze_button and not url:
            st.warning("Please enter a URL to analyze")
        else:
            # Default empty state for right column
            st.caption("Enter a URL above to view the analysis results here.")

    st.divider()
    st.caption("PhishLM analyzer • professional security assessment tool")

if __name__ == "__main__":
    main()
