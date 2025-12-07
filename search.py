from ddgs import DDGS
import tldextract
import time
from urllib.parse import urlparse


def extract_domain_for_search(url: str) -> str:
    """
    strip 'www.' 
    """
    host = urlparse(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def search(query: str,
           region: str = "us-en",
           safesearch: str = "moderate",
           timelimit: str | None = None,
           max_results: int = 20,
           page: int = 1,
           backend: str = "google"):
    """
    Generic search wrapper using DuckDuckGo Search.
    Provides a simple interface to run queries and return results.
    
    Args:
        query: search query string
        region: region code (default 'us-en')
        safesearch: safesearch level ('off', 'moderate', 'strict')
        timelimit: time filter (e.g., 'd' for day, 'w' for week, 'm' for month)
        max_results: maximum number of results to return
        page: results page number
        backend: search backend ('google', 'bing', 'duckduckgo')
    
    Returns:
        List of search results (dicts with title, href, body)
    """
    results = DDGS().text(
        query=query,
        region=region,
        safesearch=safesearch,
        timelimit=timelimit,
        max_results=max_results,
        page=page,
        backend=backend
    )
    return results

import time
from typing import List, Dict, Optional

def search_context_for_domain(target_url: str,
                              region: str = "us-en",
                              safesearch: str = "moderate",
                              timelimit: str | None = None,
                              backend: str = "brave") -> List[Dict]:
    """
    Perform multiple targeted searches for a domain.
    If a search fails, it is skipped, and only successful results are returned.
    
    Args:
        target_url: domain or URL string (e.g., 'paypal.com')
        region, safesearch, timelimit, backend: search parameters
    
    Returns:
        Combined list of deduplicated search results (list of dicts)
    """
    results = []
    queries = [
        (f'{target_url} review', 10),
        (f'{target_url} phishtank"', 8),
        (f'{target_url} is a phishing website', 20),
        (f'{target_url} "reddit"', 5),
        (f'{target_url} malware threat report', 22),
        (f'"{target_url}" scam complaints', 22),
    ]

    for query, max_results in queries:
        try:
            batch = search(
                query,
                region=region,
                safesearch=safesearch,
                timelimit=timelimit,
                max_results=max_results,
                backend=backend
            )
            if batch:
                results.extend(batch)
            time.sleep(0.1)
        except Exception as e:
            print(f"Search failed for query '{query}': {e}")
            time.sleep(0.08)  
            continue  
    seen = set()
    deduped = []
    for r in results:
        url = r.get("href", "").strip()
        if url and url not in seen:
            seen.add(url)
            deduped.append(r)

    return deduped


def expand_domain_query(domain: str) -> str:
    """
    Expand a domain into a meaningful natural-language query for RAG.
    Raises named entity presence by repeating domain variants in sentences.
    
    Args:
        domain: target domain name
    
    Returns:
        Expanded query string (natural language)
    """

    base = domain.lower()
    variants = [base, base.replace(".", ""), base.replace(".", " ")]
    variants_str = ", ".join(variants)

    query = (
        f"Is the website {base} (also written as {variants_str}) "
        f"a scam, phishing site, or involved in fraud, malware, or other threats? "
        f"Are there reviews, complaints, or discussions on Reddit, Trustpilot, or security forums "
        f"about {base} and its safety?"
    )
    return query

def format_results(results: list[dict]) -> str:
    """
    Format json into list of strings
    """
    lines = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "").strip()
        url = r.get("href", "").strip()
        snippet = r.get("body", "").strip()
        block = (
            f"{i}. Title: {title}\n"
            f"   URL: {url}\n"
            f"   Snippet: {snippet}\n"
        )
        lines.append(block)
    return lines


# site = "https://infosppl.com/"
# domain = extract_domain_for_search(site)
# ctx = search_context_for_domain(target_url=domain, backend="google")
# lines = format_results(ctx)
# from compress import rag_retrieve
# print(rag_retrieve(expand_domain_query(site), lines, 15, 0.6))
# # # ... pass `ctx` to your LLM with your analysis prompt ...
