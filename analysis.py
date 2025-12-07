import json
import time
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple
from prompts import get_p1_prompt, get_p2_prompt, get_p3_prompt

from predict_url import predict_single_url, is_valid_url
from web_parsing import is_page_live, get_short_page_text
from search import (
    extract_domain_for_search,
    search_context_for_domain,
    format_results,
    expand_domain_query 
)
from compress import rag_retrieve
from llm_interface import groq_chat, extract_json


def initialize_result_template() -> Dict[str, Any]:
    """Initialize the result template with default values."""
    return {
        "prediction": None,
        "overall_confidence": 0.0,
        "ml_phishing_prob": 0.0,
        "llm_risk_score": 0,
        "final_rationale": "",
        "safety_instructions": "",
        "used_retrieval": False,
        "error": None
    }


def run_ml_analysis(url: str) -> Tuple[float, float, Optional[str]]:
    """
    Run ML analysis on URL.
    
    Returns:
        Tuple of (ml_phish_prob, ml_conf, error_message)
    """
    try:
        ml_res = predict_single_url(url, show_details=False)
        ml_phish_prob = ml_res['phishing_probability']
        ml_conf = abs(ml_phish_prob - 0.5) * 2
        return ml_phish_prob, ml_conf, None
    except Exception as e:
        return 0.5, 0.0, f"ML analysis failed: {str(e)}"


def handle_non_live_url(ml_phish_prob: float, ml_conf: float) -> Dict[str, Any]:
    """Handle the case when URL is not live."""
    result = initialize_result_template()
    label = "PHISHING" if ml_phish_prob > 0.5 else "LEGITIMATE"
    
    result.update({
        "prediction": label,
        "overall_confidence": ml_conf,
        "ml_phishing_prob": ml_phish_prob,
        "llm_risk_score": round(ml_phish_prob * 100),
        "final_rationale": "Site is not live; assessment based on URL pattern only.",
        "safety_instructions": (
            "High risk: Do not attempt to visit; if needed, check via proxy or report as suspicious."
            if ml_phish_prob > 0.5 else
            "Low risk: Site appears legitimate based on URL, but is currently offline."
        ),
        "used_retrieval": False
    })
    return result


def run_initial_llm_analysis(url: str, ml_phish_prob: float) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Run initial LLM analysis (P1).
    
    Returns:
        Tuple of (p1_data_dict, error_message)
    """
    try:
        p1_prompt = get_p1_prompt(url, ml_phish_prob)
        p1_response = groq_chat(p1_prompt)
        p1_data = extract_json(p1_response)
        
        return {
            "risk_score": int(p1_data["risk_score"]),
            "certainty": float(p1_data["certainty"]),
            "retrieve": str(p1_data["retrieve"]),
            "initial_rationale": str(p1_data["initial_rationale"])
        }, None
    except Exception as e:
        return {}, f"LLM P1 failed: {str(e)}"


def retrieve_additional_content(retrieve_type: str, url: str) -> str:
    """
    Retrieve additional content based on the retrieve type.
    
    Args:
        retrieve_type: "pageContent" or "searchResults"
        url: The URL to analyze
    
    Returns:
        Retrieved content as string
    """
    content = "No additional data available."
    

    if retrieve_type == "pageContent":
        raw_text = get_short_page_text(url)
        if raw_text.strip():
            content = f"Page Content:\n{raw_text}"
            
    if retrieve_type == "searchResults":
        domain = extract_domain_for_search(url)
        ctx = search_context_for_domain(domain, backend="google")
        if ctx:
            lines = format_results(ctx)
            if lines:
                query = expand_domain_query(domain)
                summary = "\n".join(rag_retrieve(query=query, source=lines, top_k=15, min_score=0.6))
                if summary.strip():
                    content = f"Search Results:\n{summary}"

    
    return content


def run_safety_only_analysis(url: str, ml_phish_prob: float, 
                           initial_risk_score: int, initial_rationale: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Run safety-only analysis (P3).
    
    Returns:
        Tuple of (result_dict, error_message)
    """
    try:
        p3_prompt = get_p3_prompt(url, ml_phish_prob, initial_risk_score, initial_rationale)
        p3_response = groq_chat(p3_prompt)
        p3_data = extract_json(p3_response)
        
        return {
            "final_risk_score": initial_risk_score,
            "final_rationale": p3_data["final_rationale"],
            "safety_instructions": p3_data["safety_instructions"]
        }, None
    except Exception as e:
        # Fallback safety instructions
        if initial_risk_score >= 70:
            safety = "Do not visit. Report to authorities if received via email."
        elif initial_risk_score >= 30:
            safety = "If you must visit, use incognito mode and never enter credentials."
        else:
            safety = "Appears safe, but remain cautious with downloads or logins."
        
        return {
            "final_risk_score": initial_risk_score,
            "final_rationale": initial_rationale,
            "safety_instructions": safety
        }, f"P3 safety prompt failed: {str(e)}"


def run_context_refined_analysis(url: str, ml_phish_prob: float, initial_risk_score: int,
                               initial_rationale: str, additional_content: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Run context-refined analysis (P2).
    
    Returns:
        Tuple of (result_dict, error_message)
    """
    try:
        p2_prompt = get_p2_prompt(url, ml_phish_prob, initial_risk_score, 
                                 initial_rationale, additional_content)
        p2_response = groq_chat(p2_prompt)
        p2_data = extract_json(p2_response)
        
        return {
            "final_risk_score": int(p2_data["final_risk_score"]),
            "final_rationale": p2_data["final_rationale"],
            "safety_instructions": p2_data["safety_instructions"]
        }, None
    except Exception as e:
        # Fallback to initial score + generic safety
        if initial_risk_score >= 70:
            safety = "Do not visit. Report to authorities if received via email."
        elif initial_risk_score >= 30:
            safety = "If you must visit, use incognito mode and never enter credentials."
        else:
            safety = "Appears safe, but remain cautious with downloads or logins."
        
        return {
            "final_risk_score": initial_risk_score,
            "final_rationale": initial_rationale,
            "safety_instructions": safety
        }, f"P2 refined prompt failed: {str(e)}"


def compute_final_results(ml_phish_prob: float, ml_conf: float, 
                         final_risk_score: int, final_rationale: str,
                         safety_instructions: str, used_retrieval: bool) -> Dict[str, Any]:
    """
    Compute final results with fusion of ML and LLM scores.
    
    Returns:
        Complete result dictionary
    """
    result = initialize_result_template()
    
    # Fusion calculation
    llm_prob = final_risk_score / 100.0
    final_prob = 0.2 * ml_phish_prob + 0.8 * llm_prob
    label = "PHISHING" if final_prob > 0.5 else "LEGITIMATE"
    overall_confidence = (ml_conf + (final_risk_score / 100.0)) / 2.0
    
    result.update({
        "prediction": label,
        "overall_confidence": min(overall_confidence, 1.0),
        "ml_phishing_prob": ml_phish_prob,
        "llm_risk_score": final_risk_score,
        "final_rationale": final_rationale,
        "safety_instructions": safety_instructions,
        "used_retrieval": used_retrieval
    })
    
    return result


def run_phishllm_analysis(url: str) -> Dict[str, Any]:
    """
    Full  pipeline for a single URL.
    Returns:
        dict with keys: prediction, overall_confidence, ml_phishing_prob,
        llm_risk_score, final_rationale, safety_instructions, used_retrieval, error
    """

    if not is_valid_url(url):
        result = initialize_result_template()
        result["error"] = "Invalid URL, please provide a valid web address starting with http:// or https://."
        return result

    ml_phish_prob, ml_conf, ml_error = run_ml_analysis(url)
    if ml_error:
        result = initialize_result_template()
        result["error"] = ml_error
        return result

    is_live = is_page_live(url)
    if not is_live:
        return handle_non_live_url(ml_phish_prob, ml_conf)

    p1_data, p1_error = run_initial_llm_analysis(url, ml_phish_prob)
    if p1_error:
        # Fallback to ML if LLM fails
        result = initialize_result_template()
        result.update({
            "prediction": "PHISHING" if ml_phish_prob > 0.5 else "LEGITIMATE",
            "overall_confidence": ml_conf,
            "ml_phishing_prob": ml_phish_prob,
            "llm_risk_score": round(ml_phish_prob * 100),
            "final_rationale": f"LLM analysis failed; falling back to ML: {p1_error}",
            "safety_instructions": "Exercise caution. Analysis incomplete due to technical error.",
            "used_retrieval": False,
            "error": p1_error
        })
        return result

    initial_risk_score = p1_data["risk_score"]
    certainty = p1_data["certainty"]
    retrieve = p1_data["retrieve"]
    initial_rationale = p1_data["initial_rationale"]


    if retrieve == "none":
        # Use P3: Safety-Only (no re-assessment)
        p3_result, p3_error = run_safety_only_analysis(url, ml_phish_prob, 
                                                      initial_risk_score, initial_rationale)
        final_risk_score = p3_result["final_risk_score"]
        final_rationale = p3_result["final_rationale"]
        safety_instructions = p3_result["safety_instructions"]
        used_retrieval = False
        error = p3_error
    else:
        # Attempt retrieval and use P2
        used_retrieval = True
        additional_content = retrieve_additional_content(retrieve, url)
        
        p2_result, p2_error = run_context_refined_analysis(url, ml_phish_prob, 
                                                          initial_risk_score, 
                                                          initial_rationale, 
                                                          additional_content)
        final_risk_score = p2_result["final_risk_score"]
        final_rationale = p2_result["final_rationale"]
        safety_instructions = p2_result["safety_instructions"]
        error = p2_error
    return compute_final_results(
        ml_phish_prob=ml_phish_prob,
        ml_conf=ml_conf,
        final_risk_score=final_risk_score,
        final_rationale=final_rationale,
        safety_instructions=safety_instructions,
        used_retrieval=used_retrieval
    )


# print(run_phishllm_analysis("https://www.shopperspk.com/cart/"))