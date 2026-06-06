import os
import requests

GOOGLE_API_KEY = os.getenv("GOOGLE_FACT_CHECK_API_KEY", "")
NEWS_API_KEY   = os.getenv("NEWS_API_KEY", "")

def search_fact_check(query: str) -> list:
    if not GOOGLE_API_KEY:
        return []
    try:
        url    = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
        params = {"query": query[:200], "key": GOOGLE_API_KEY, "pageSize": 3}
        resp   = requests.get(url, params=params, timeout=5)
        data   = resp.json()
        claims = []
        for item in data.get("claims", []):
            review = item.get("claimReview", [{}])[0]
            claims.append({
                "claim":      item.get("text", ""),
                "rating":     review.get("textualRating", ""),
                "publisher":  review.get("publisher", {}).get("name", ""),
                "url":        review.get("url", ""),
            })
        return claims
    except:
        return []

def search_news(query: str) -> list:
    if not NEWS_API_KEY:
        return []
    try:
        words  = [w for w in query.split() if len(w) > 4][:6]
        q      = " ".join(words)
        url    = "https://newsapi.org/v2/everything"
        params = {
            "q":        q,
            "sortBy":   "relevancy",
            "pageSize": 3,
            "apiKey":   NEWS_API_KEY,
            "language": "en",
        }
        resp    = requests.get(url, params=params, timeout=5)
        data    = resp.json()
        sources = []
        for article in data.get("articles", []):
            sources.append({
                "title":       article.get("title", ""),
                "source":      article.get("source", {}).get("name", ""),
                "url":         article.get("url", ""),
                "published_at": article.get("publishedAt", ""),
            })
        return sources
    except:
        return []

def fact_check(text: str) -> dict:
    first_sentence = text.strip().split(".")[0][:200]
    fact_claims    = search_fact_check(first_sentence)
    news_sources   = search_news(first_sentence)
    return {
        "fact_check_results": fact_claims,
        "related_sources":    news_sources,
        "sources_found":      len(news_sources),
    }