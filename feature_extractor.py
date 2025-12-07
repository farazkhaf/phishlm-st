import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any


import tldextract


# Popular tld
POPULAR_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'co', 'uk', 'de', 'jp', 'fr',
    'au', 'us', 'ru', 'ch', 'it', 'nl', 'se', 'no', 'es', 'mil',
    'ca', 'in', 'br', 'za', 'cn', 'mx', 'tw', 'pl', 'be', 'at'
}

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.zip', '.rar', '.tar', '.gz', '.7z', '.bin', '.bat',
    '.sh', '.cmd', '.apk', '.app', '.deb', '.rpm', '.msi', '.dmg'
}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher values indicate more randomness/complexity.
    
    Args:
        text: Input string
        
    Returns:
        Shannon entropy value (0.0 if empty string)
    """
    if not text:
        return 0.0
    
    # character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # entropy
    length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def count_tokens(url: str) -> int:
    """
    Count number of tokens/words in URL.
    Splits by common delimiters: / - _ . ? & =
    
    Args:
        url: URL string
        
    Returns:
        Number of tokens
    """
    # Split by common separator
    tokens = re.split(r'[/\-_.?&=]', url)
    # remove empty strings
    tokens = [t for t in tokens if t]
    return len(tokens)


def has_ip_address(url: str) -> int:
    # IPv4 pattern
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return 1 if re.search(ipv4_pattern, url) else 0


def check_suspicious_extension(url: str) -> int:
    url_lower = url.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if url_lower.endswith(ext):
            return 1
    return 0


def extract_features(url: str) -> Dict[str, Any]:
    """   
    1. url_length - Total characters in URL
    2. has_ip_address - Binary flag for IP address presence
    3. dot_count - Number of dots in URL
    4. https_flag - Binary flag for HTTPS usage
    5. url_entropy - Shannon entropy of URL string
    6. token_count - Number of tokens/words in URL
    7. subdomain_count - Number of subdomains
    8. query_param_count - Number of query parameters
    9. tld_length - Length of top-level domain
    10. path_length - Length of path after domain
    11. has_hyphen_in_domain - Binary flag for hyphen in domain
    12. number_of_digits - Total numeric characters
    13. tld_popularity - Binary flag for popular TLD
    14. suspicious_file_extension - Binary flag for suspicious extensions
    15. domain_name_length - Length of domain name
    16. percentage_numeric_chars - Percentage of numeric characters
    
    Args:
        url: URL string to analyze
        
    Returns:
        Dictionary with 16 feature key-value pair
    """
    
    features = {
        'url_length': 0,
        'has_ip_address': 0,
        'dot_count': 0,
        'https_flag': 0,
        'url_entropy': 0.0,
        'token_count': 0,
        'subdomain_count': 0,
        'query_param_count': 0,
        'tld_length': 0,
        'path_length': 0,
        'has_hyphen_in_domain': 0,
        'number_of_digits': 0,
        'tld_popularity': 0,
        'suspicious_file_extension': 0,
        'domain_name_length': 0,
        'percentage_numeric_chars': 0.0
    }
    
    try:
        features['url_length'] = len(url)
        features['dot_count'] = url.count('.')
        features['has_ip_address'] = has_ip_address(url)
        features['url_entropy'] = calculate_entropy(url)
        features['token_count'] = count_tokens(url)
        features['suspicious_file_extension'] = check_suspicious_extension(url)
        
        # digits
        features['number_of_digits'] = sum(c.isdigit() for c in url)
        
        # percentage of numeric characters
        if features['url_length'] > 0:
            features['percentage_numeric_chars'] = (
                features['number_of_digits'] / features['url_length']
            ) * 100
        
        # Parse URL components
        parsed = urlparse(url)
        
        # HTTPS flag
        features['https_flag'] = 1 if parsed.scheme == 'https' else 0
        
 
        features['path_length'] = len(parsed.path)

        if parsed.query:
            query_params = parse_qs(parsed.query)
            features['query_param_count'] = len(query_params)
        
        # domain components
        extracted = tldextract.extract(url)
        domain = extracted.domain
        subdomain = extracted.subdomain
        tld = extracted.suffix
        
        features['domain_name_length'] = len(domain)
        features['has_hyphen_in_domain'] = 1 if '-' in domain else 0

        features['tld_length'] = len(tld.replace('.', ''))  # Remove dots from multi-part TLDs
        

        tld_base = tld.split('.')[-1] if tld else ''
        features['tld_popularity'] = 1 if tld_base in POPULAR_TLDS else 0
        
        if subdomain:
            subdomain_parts = [s for s in subdomain.split('.') if s]
            features['subdomain_count'] = len(subdomain_parts)
        
    except Exception as e:
        print(f"Warning: Error extracting from URL: {e}")
        pass
    
    return features


def extract_features_batch(urls: list) -> list:
    return [extract_features(url) for url in urls]

