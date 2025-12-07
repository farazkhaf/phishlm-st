def get_p1_prompt(url: str, ml_phish_prob: float) -> str:
    """
    P1: Initial LLM analysis (URL-only)
    Decides whether additional context is needed
    """
    return f"""You are a cybersecurity assistant analyzing phishing risk from a URL.

Input:
- URL: {url}
- ML Model Phishing Probability: {ml_phish_prob:.2f} (Note: This model uses only URL syntax and is unreliable for modern HTTPS phishing sites and can give high False positives. Treat it as very weak hint or just ignore it.)

Your task:
1. Analyze the URL for phishing indicators (e.g., domain mimicry, unusual TLDs, IP addresses, excessive subdomains, typos, deceptive words).
2. Assign a Phishing Risk Score from 0 to 100 (0 = definitely legitimate, 100 = definite phishing).
3. Self-assess your Certainty from 0.0 to 1.0 (1.0 = obvious scam like 'paypa1-login.com'; 0.0 = ambiguous).
4. Decide what additional data, if any, would most improve accuracy:
   - "none" if certainty > 0.8 or risk is obvious
   - "pageContent" if you suspect semantic lures (e.g., fake login forms, urgency) that require page text (and must be validated)
   - "searchResults" if the domain might have public reports (e.g., new scam, known brand impersonation, popular terms), it will retrieve search snippets.
   - "both" will retrieve both pageContent and searchResults; be careful and choose only what is strictly necessary. too much info may cause noise.
Output ONLY a valid JSON object with keys:
{{"risk_score": int, "certainty": float, "retrieve": str, "initial_rationale": str}}

Keep "initial_rationale" under 50 words. Be concise.
"""


def get_p2_prompt(url: str, ml_phish_prob: float, initial_risk_score: int, 
                  initial_rationale: str, additional_content: str) -> str:
    """
    P2: Context-refined analysis
    Re-evaluates with additional context (page content or search results)
    """
    return f"""You are an official cybersecurity assistant refining a phishing risk assessment using additional context.

Original Input:
- URL: {url}
- ML Phishing Probability (Weak Hint): {ml_phish_prob:.2f} (Note: This model uses only URL syntax and is unreliable for modern HTTPS phishing sites and can give high False positives. Treat it as very weak hint or just ignore it.)
- Initial LLM Risk Score: {initial_risk_score}
- Initial Rationale: "{initial_rationale}"

Additional Context:
{additional_content}

Instructions:
1. Re-evaluate the phishing risk (0–100) using the additional context.
   - If context is "No additional data available.", rely only on URL or weak ML hint (go neutral if unsure/not enough info) Extraction limitation could be due to our own capablitiy limit.
   - If page content: look for fake forms, brand mimicry, urgency, mismatched sender or other phishing cues.
    -Lean towards slightly <50 risk if obtained page's no code/form/body element indicates phishing, but overall uncertain.
   - If search results: prioritize credible reports, match domain carefully, ignore irrelevant results like generic ads.
   - if you have credible sources or facts, try to mention 2-3 shortly in final_rationale.
2. Provide a concise Final Rationale (<100 words).
3. Generate tiered Safety Instruction for user based on final risk and available context. (Example; Do not visit, use incognito, do not download or enter creds, etc write based on available context and scenario). Be concise and actionable.
   -

Output ONLY a valid JSON object with keys:
{{"final_risk_score": int, "final_rationale": str, "safety_instructions": str}}
"""


def get_p3_prompt(url: str, ml_phish_prob: float, initial_risk_score: int, 
                  initial_rationale: str) -> str:
    """
    P3: Safety-only prompt
    Used when no additional retrieval is needed (high certainty)
    """
    return f"""You are an official cybersecurity assistant providing safety guidance.

Initial Assessment:
- URL: {url}
- ML Phishing Probability: {ml_phish_prob:.2f}
- Initial Risk Score: {initial_risk_score}
- Rationale: "{initial_rationale}"

Instructions:
Generate clear safety instructions based ONLY on this initial assessment.
Do NOT change the risk score or rationale.
Provide tiered advice:
- High risk (70–100): Do not visit. Report to authorities if received via email. (ETC, choose text according to context.)
- Medium risk (30–69): If you must visit, use incognito mode and never enter credentials... or whatever is suitable.
- Low risk (0–29): Appears safe, but remain cautious or ... as suitable.

Output ONLY a valid JSON object with keys:
{{"final_rationale": str, "safety_instructions": str}}
"""
