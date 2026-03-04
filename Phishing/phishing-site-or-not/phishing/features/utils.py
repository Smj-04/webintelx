"""Utilities: logging, JSON output, input validation, rate-limiting, dependency checks."""
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from functools import wraps
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        # always write log lines to stderr so stdout remains clean for JSON output
        logging.StreamHandler(sys.stderr),
        logging.FileHandler('phishing_detection.log')
    ]
)

logger = logging.getLogger(__name__)


class URLValidator:
    """Validate and sanitize URLs."""
    
    @staticmethod
    def validate(url: str) -> Optional[str]:
        """Return sanitized URL if valid, else None."""
        if not url:
            logger.warning("Empty URL provided")
            return None
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        # Basic URL regex
        url_pattern = re.compile(
            r'^https?://'  # http or https
            r'(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)'  # domain
            r'(?::\d{2,5})?'  # optional port
            r'(?:[/?#][^\s]*)?$',  # optional path
            re.IGNORECASE
        )
        if url_pattern.match(url):
            logger.info(f"URL validated: {url}")
            return url
        logger.warning(f"Invalid URL format: {url}")
        return None


class RateLimiter:
    """Rate limiter to prevent abuse."""
    
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests = []
    
    def is_allowed(self) -> bool:
        """Check if request is allowed within rate limit."""
        now = datetime.utcnow()
        # Remove old requests outside window
        self.requests = [t for t in self.requests if now - t < self.window]
        
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        
        logger.warning(f"Rate limit exceeded: {len(self.requests)}/{self.max_requests} in {self.window.total_seconds()}s")
        return False


class JSONOutput:
    """Serialize analysis results to JSON."""
    
    @staticmethod
    def format(url: str, verdict: str, confidence: str, risk_score: float, 
               breakdown: Dict[str, Any], model_pred: str, model_conf: float) -> str:
        """Return JSON-formatted output."""
        output = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "verdict": verdict,
            "confidence": confidence,
            "overall_risk_score": risk_score,
            "breakdown": breakdown,
            "model_prediction": {
                "result": model_pred,
                "confidence": model_conf
            }
        }
        return json.dumps(output, indent=2)


def check_dependencies() -> Dict[str, bool]:
    """Check if critical async/network dependencies are available."""
    deps = {
        "aiohttp": False,
        "whois": False,
        "asyncio": True  # built-in
    }
    
    try:
        import aiohttp
        deps["aiohttp"] = True
        logger.info("aiohttp available for async fetching")
    except ImportError:
        logger.warning("aiohttp not available; falling back to sync requests")
    
    try:
        import whois
        deps["whois"] = True
        logger.info("whois available for domain age lookups")
    except ImportError:
        logger.warning("whois not available; domain age lookups disabled")
    
    return deps


rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
validator = URLValidator()
