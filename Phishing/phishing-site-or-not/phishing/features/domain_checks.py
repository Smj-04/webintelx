import socket
import ssl
import time
from datetime import datetime
from functools import wraps

# Simple in-memory TTL cache
def ttl_cache(ttl_seconds=60):
    def deco(fn):
        cache = {}

        @wraps(fn)
        def wrapped(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            now = time.time()
            if key in cache:
                ts, val = cache[key]
                if now - ts < ttl_seconds:
                    return val
            val = fn(*args, **kwargs)
            cache[key] = (now, val)
            return val

        return wrapped

    return deco

def resolve_domain(domain, timeout=5):
    """Return True if domain resolves to an IP address."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


# cached version
resolve_domain = ttl_cache(ttl_seconds=300)(resolve_domain)


def get_ssl_days_left(domain, timeout=5):
    """Return number of days until SSL certificate expires, or None if unavailable."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # cert['notAfter'] like 'Jun 10 12:00:00 2026 GMT'
                not_after = cert.get('notAfter')
                if not not_after:
                    return None
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                delta = exp - datetime.utcnow()
                return max(0, delta.days)
    except Exception:
        return None


# cached ssl check for performance
get_ssl_days_left = ttl_cache(ttl_seconds=300)(get_ssl_days_left)


def get_domain_age_days(domain):
    """Try to get domain age in days via whois; returns None if whois not available or fails."""
    try:
        import whois
    except Exception:
        return None

    try:
        info = whois.whois(domain)
        # whois lib may provide creation_date as datetime or list
        cd = info.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None
        if isinstance(cd, str):
            try:
                # try parsing common formats
                cd = datetime.fromisoformat(cd)
            except Exception:
                return None
        delta = datetime.utcnow() - cd
        return max(0, delta.days)
    except Exception:
        return None
