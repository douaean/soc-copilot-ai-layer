from typing import Any
from urllib.parse import quote_plus


def search_tavily(query: str) -> dict[str, Any]:
    """Search the Tavily web site for threat intelligence context.

    This function uses a live web request when possible but falls back to a
    structured placeholder summary if the site cannot be reached.
    """
    try:
        import httpx
    except ImportError:
        return {
            "source": "tavily.com",
            "summary": "Threat intelligence search is unavailable because httpx is not installed.",
            "confidence": 0.0,
            "details": [],
        }

    query_text = query or "security alert"
    search_url = f"https://www.tavily.com/search?query={quote_plus(query_text)}"

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(search_url)
            response_text = response.text
    except Exception as exc:
        return {
            "source": "tavily.com",
            "summary": (
                "Unable to fetch Tavily threat intelligence in this environment; "
                "using fallback guidance instead."
            ),
            "confidence": 0.0,
            "details": [str(exc)],
        }

    summary_lines = []
    if response.status_code == 200 and response_text:
        summary_lines.append(
            f"Retrieved Tavily page title: {response_text.split('<title>')[1].split('</title>')[0]}"
            if "<title>" in response_text else "Retrieved Tavily content."
        )
        if "No results" in response_text or "no results" in response_text.lower():
            summary_lines.append("Tavily returned no direct threat intelligence results for this query.")
        else:
            summary_lines.append("Tavily search returned a page that can be reviewed for related threat intelligence.")
    else:
        summary_lines.append("Tavily search returned an unexpected response status.")

    return {
        "source": "tavily.com",
        "summary": " ".join(summary_lines),
        "confidence": 0.5 if response.status_code == 200 else 0.2,
        "details": [search_url],
    }
