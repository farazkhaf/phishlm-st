import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse 
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
}
TIMEOUT = 12  


def is_page_live(url: str) -> bool:
    """
    Checks if the URL is reachable and returns a successful HTTP status.
    Returns True if live (status 200), False otherwise (404, timeout, redirect loop, etc.).
    """
    try:
        response = requests.head(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False  # Skip SSL errors 
        )
        return response.status_code == 200
    except Exception:
        return False


def get_full_page_text(url: str) -> str:
    """
    Returns the full visible text from <body> as a single string.
    Returns empty string on failure.
    """
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup(["script", "style", "noscript", "meta", "link"]):
            script.decompose()
        body = soup.body
        if not body:
            return ""

        text = body.get_text(separator="\n", strip=True)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    except Exception:
        return ""  





def get_short_page_text(url: str, max_words: int = 800) -> str:
    """
    Extracts page elements for LLM analysis. Returns structured string.
    """
    try:
        max_tokens = max_words * 1.5
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        parsed_url = urlparse(url)
        
        elements = []
        
        # BASIC INFO
        elements.append(f"URL: {url}")
        elements.append(f"Domain: {parsed_url.netloc}")
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        elements.append(f"Title: {title}")
        
        # FORMS - capture more context
        forms = soup.find_all("form")
        if forms:
            elements.append(f"\nFORMS ({len(forms)}):")
            for i, form in enumerate(forms[:3], 1):  
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                enctype = form.get("enctype", "")
                
                # Include encoding type for file uploads
                form_info = f"  Form {i}: {method}"
                if action:
                    action_domain = urlparse(action).netloc if action.startswith("http") else parsed_url.netloc
                    form_info += f" -> {action} (domain: {action_domain})"
                else:
                    form_info += " -> (same page)"
                
                if enctype:
                    form_info += f" [enctype={enctype}]"
                
                elements.append(form_info)
                
                inputs = form.find_all(["input", "textarea", "select"])
                if inputs:
                    fields = []
                    for inp in inputs[:12]:  
                        input_type = inp.get("type", "text")
                        name = inp.get("name", "")
                        placeholder = inp.get("placeholder", "")
                        value = inp.get("value", "")
                        hidden = inp.get("type") == "hidden"
                        required = inp.has_attr("required")
                        autocomplete = inp.get("autocomplete", "")
                        
                        field_info = f"{input_type}"
                        if name:
                            field_info += f"[name={name}]"
                        if placeholder:
                            field_info += f"[placeholder={placeholder}]"
                        if value and input_type != "password":  # Don't expose password values
                            field_info += f"[value={value}]"
                        if hidden:
                            field_info += "[HIDDEN]"
                        if required:
                            field_info += "[REQUIRED]"
                        if autocomplete:
                            field_info += f"[autocomplete={autocomplete}]"
                            
                        fields.append(field_info)
                    
                    elements.append(f"    Fields: {', '.join(fields)}")
        
        # EXTERNAL REFERENCES
        links = soup.find_all("a", href=True)
        external_domains = set()
        for link in links:
            href = link["href"]
            if href.startswith("http"):
                link_domain = urlparse(href).netloc
                if link_domain and link_domain != parsed_url.netloc:
                    external_domains.add(f"{link_domain} -> {href}")
        
        if external_domains:
            elements.append(f"\nEXTERNAL LINKS ({len(external_domains)}):")
            for ext_link in list(external_domains)[:10]:
                elements.append(f"  {ext_link}")
        
        # IFRAMES - include more context
        iframes = soup.find_all("iframe")
        if iframes:
            elements.append(f"\nIFRAMES ({len(iframes)}):")
            for iframe in iframes[:5]:  # Increased from 3
                src = iframe.get("src", "")
                srcdoc = iframe.get("srcdoc", "")[:100] if iframe.get("srcdoc") else ""
                
                if src:
                    iframe_domain = urlparse(src).netloc if src.startswith("http") else parsed_url.netloc
                    elements.append(f"  src: {src} (domain: {iframe_domain})")
                if srcdoc:
                    elements.append(f"  srcdoc preview: {srcdoc}...")
        
        # META TAGS
        meta_refresh = soup.find("meta", attrs={"http-equiv": "refresh"})
        if meta_refresh:
            content = meta_refresh.get("content", "")
            elements.append(f"\nMETA REFRESH: {content}")
        
        # Remove non-content elements
        for tag in soup(["script", "style", "nav", "footer", "aside"]):
            tag.decompose()
        
        # INCREASED TEXT SAMPLING
        body_text = soup.body.get_text(separator=" ", strip=True) if soup.body else ""
        visible_words = " ".join(body_text.split()[:1200])  # Increased from 400
        if visible_words:
            elements.append(f"\nVISIBLE TEXT ({len(visible_words.split())} words):\n{visible_words}")
        
        result = "\n".join(elements)
        
        if len(result) > max_tokens * 4:
            result = result[:int(max_tokens * 4)] + "...[truncated]"
        
        return result
        
    except Exception as e:
        return f"Error fetching page: {str(e)}"
