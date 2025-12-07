import sys
from feature_extractor import extract_features
from ml_classifier import load_model, predict_proba
from urllib.parse import urlparse

def is_valid_url(url: str) -> bool:

    if not isinstance(url, str) or not url.strip():
        return False
    
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return False

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not host:
            return False
        if host.startswith("www."):
            host = host[4:]
        if host != "localhost" and "." not in host:
            return False
        return True
    except Exception:
        return False

FEATURE_NAMES = [
    'url_length',
    'has_ip_address',
    'dot_count',
    'https_flag',
    'url_entropy',
    'token_count',
    'subdomain_count',
    'query_param_count',
    'tld_length',
    'path_length',
    'has_hyphen_in_domain',
    'number_of_digits',
    'tld_popularity',
    'suspicious_file_extension',
    'domain_name_length',
    'percentage_numeric_chars'
]

MODEL_PATH = "models/phishing_model.cbm"


def predict_single_url(url: str, model=MODEL_PATH, feature_names: list = FEATURE_NAMES, show_details: bool = True):
    """
    Predict if a URL is phishing or legitimate.
    
    Args:
        url: URL string to analyze
        model: Loaded CatBoost model
        feature_names: List of feature names in training order
        show_details: Whether to print detailed analysis
        
    Returns:
        dict with prediction results
    """
    features = extract_features(url)
    model = load_model(model)
    phishing_prob = predict_proba(model, features, feature_names)
    legitimate_prob = 1.0 - phishing_prob
    
    is_phishing = phishing_prob > 0.5
    confidence = phishing_prob if is_phishing else legitimate_prob
    
    result = {
        'url': url,
        'is_phishing': bool(is_phishing),
        'prediction': 'PHISHING' if is_phishing else 'LEGITIMATE',
        'confidence': float(confidence),
        'phishing_probability': float(phishing_prob),
        'legitimate_probability': float(legitimate_prob),
        'features': features
    }
    
    
    return result


