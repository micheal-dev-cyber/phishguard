# src/url_intel.py

import requests
import tldextract


def get_redirect_chain(url):
    """Traces the redirect chain of a URL."""
    chain = [url]
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        for history in response.history:
            chain.append(history.url)
        chain.append(response.url)
    except Exception as e:
        chain.append(f"Error: {str(e)}")
    return list(dict.fromkeys(chain))  # Remove duplicates preserving order

def analyze_url_safety(url):
    """Performs a deep look at the final destination."""
    chain = get_redirect_chain(url)
    final_url = chain[-1]
    ext = tldextract.extract(final_url)

    return {
        "final_url": final_url,
        "domain": f"{ext.domain}.{ext.suffix}",
        "is_shortened": any(s in url for s in ['bit.ly', 't.co', 'goo.gl', 'tinyurl']),
        "chain_length": len(chain),
        "chain": chain
    }
