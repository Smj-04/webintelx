"""
typosquat_detector.py

Purpose: Heuristic typosquatting / lookalike domain detection for backend integration.

How to use:
    from typosquat_detector import is_domain_suspicious, integrate_flask_middleware

    legit = ['example.com', 'mycompany.com', 'secure.example.co']
    domain = 'examp1e.com'
    score, reasons, action = is_domain_suspicious(domain, legit)
"""

from typing import List, Tuple, Dict, Any
import unicodedata
import re
import idna
import sys

# Try to use rapidfuzz for better fuzzy matching; otherwise fallback to difflib
try:
    from rapidfuzz import fuzz, distance as rdistance
    _HAS_RAPIDFUZZ = True
except Exception:
    _HAS_RAPIDFUZZ = False
    from difflib import SequenceMatcher

# ---------- Configuration / thresholds (tune these) ----------
DEFAULT_THRESHOLDS = {
    "edit_distance_ratio_warn": 0.85,   # normalized similarity >= 0.85 means suspicious (0..1)
    "edit_distance_ratio_block": 0.92,  # very close -> high suspicion
    "substring_ratio": 0.6,             # e.g., "examp" vs "example"
    "length_ratio_extreme": 0.5,        # extremely shorter/longer suspicious
    "repeated_char_runs": 3,            # repeated char runs (aaaa) suspicious
}

# ---------- Helpers ----------
def normalize_domain(domain: str) -> str:
    """Lowercase and NFC-normalize. Strip trailing dot."""
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    # Normalize Unicode to NFC
    domain = unicodedata.normalize('NFC', domain)
    return domain

def to_ascii(domain: str) -> str:
    """Return ASCII / punycode form when possible. If idna decode fails, return input."""
    try:
        # idna.encode returns bytes; decode to str
        return idna.encode(domain).decode('ascii')
    except Exception:
        # If already ascii-ish or encoding fails, return original
        return domain

def contains_non_latin(domain: str) -> bool:
    """Detect presence of non-latin Unicode characters (possible homoglyph/homograph attempt)."""
    for ch in domain:
        if ch.isascii():
            continue
        cat = unicodedata.name(ch, '')
        # Basic heuristic: if script is not LATIN, flag
        if 'LATIN' not in cat:
            return True
    return False

def get_tld_and_sld(domain: str) -> Tuple[str, str]:
    """
    Very lightweight split: returns (sld, tld)
    e.g. "login.example.co.uk" -> sld "example", tld "co.uk" (approx.)
    NOTE: This is heuristic (doesn't use full public suffix list). For production, use publicsuffix2.
    """
    parts = domain.split('.')
    if len(parts) == 1:
        return parts[0], ''
    if len(parts) >= 3:
        # try to treat last two as tld (co.uk style)
        return parts[-2], '.'.join(parts[-2:])
    else:
        return parts[-2], parts[-1]

def normalized_edit_similarity(a: str, b: str) -> float:
    """Return similarity normalized 0..1 (higher => more similar)."""
    if _HAS_RAPIDFUZZ:
        # use token sort ratio? use Levenshtein normalized similarity
        try:
            # Rapidfuzz's normalized similarity gives between 0..100
            sim = rdistance.DamerauLevenshtein.normalized_similarity(a, b)  # 0..100
            return sim / 100.0
        except Exception:
            return fuzz.ratio(a, b) / 100.0
    else:
        # fallback using SequenceMatcher ratio (not ideal for some edits)
        return SequenceMatcher(None, a, b).ratio()

def substring_similarity(a: str, b: str) -> float:
    """Compute a substring-based ratio (longest common substring / max length)."""
    a, b = a.lower(), b.lower()
    # naive longest substring:
    maxlen = 0
    la, lb = len(a), len(b)
    for i in range(la):
        for j in range(i + 1, la + 1):
            sub = a[i:j]
            idx = b.find(sub)
            if idx != -1 and len(sub) > maxlen:
                maxlen = len(sub)
    if maxlen == 0:
        return 0.0
    return maxlen / max(la, lb)

def repeated_char_runs(domain: str) -> bool:
    """Detect runs like 'aaaa' or 'llll' more than threshold."""
    runs = re.findall(r'(.)\1{2,}', domain)  # 3 or more repeating chars
    return len(runs) > 0

def token_similarity(domain: str, legit: str) -> float:
    """
    Check token-level similarity: e.g., 'secure-login.example' vs 'example.com'
    Strip common prefixes like 'www', 'login', 'secure' for comparison.
    """
    prefix_stop = {'www', 'login', 'secure', 'mail', 'accounts', 'app', 'signin', 'pay'}
    def clean_tokens(s):
        parts = re.split(r'[\.\-]', s)
        return [p for p in parts if p and p not in prefix_stop]
    da = clean_tokens(domain)
    db = clean_tokens(legit)
    if not da or not db:
        return 0.0
    # Fraction of tokens in common
    common = sum(1 for t in da if t in db)
    return common / max(len(db), 1)

# ---------- Main detection function ----------
def is_domain_suspicious(domain: str,
                         legit_domains: List[str],
                         thresholds: Dict[str, float] = None
                         ) -> Tuple[float, List[str], str]:
    """
    Score domain against a list of legitimate domains.
    Returns: (score 0..1, reasons list, suggested_action)
    - score: higher means more suspicious
    - reasons: human-readable reasons for flagging
    - suggested_action: "allow", "warn", or "block"
    """
    thresholds = thresholds or DEFAULT_THRESHOLDS
    domain = normalize_domain(domain)
    ascii_domain = to_ascii(domain)
    reasons = []
    highest_score = 0.0
    matched_legit = None

    # Quick sanity: if identical to any legit -> allow
    for L in legit_domains:
        if domain == normalize_domain(L) or ascii_domain == to_ascii(normalize_domain(L)):
            return 0.0, ["Exact match to trusted domain"], "allow"

    # Heuristic checks
    nonlatin = contains_non_latin(domain)
    if nonlatin:
        reasons.append("Contains non-Latin characters (possible homograph).")
        highest_score = max(highest_score, 0.6)

    # Punycode detection
    if domain.startswith('xn--') or 'xn--' in ascii_domain:
        reasons.append("Punycode (IDN) detected — possible homograph via Unicode.")
        highest_score = max(highest_score, 0.65)

    # repeated char runs
    if repeated_char_runs(domain):
        reasons.append("Long repeated character runs detected.")
        highest_score = max(highest_score, 0.55)

    # length ratio extremes vs each legit domain
    for legit in legit_domains:
        ld = normalize_domain(legit)
        a = domain
        b = ld
        # Compare full domain names and SLD specifically
        sim_full = normalized_edit_similarity(a, b)
        sim_sub = substring_similarity(a, b)
        token_sim = token_similarity(a, b)

        # Also compare SLDs (second level domain) to avoid tld changes
        sld_a, tld_a = get_tld_and_sld(a)
        sld_b, tld_b = get_tld_and_sld(b)
        sld_sim = normalized_edit_similarity(sld_a, sld_b)

        # Build score components (weights can be tuned)
        score = 0.0
        # primary: full-name edit similarity
        score = max(score, sim_full * 0.6)
        # sld similarity matters strongly
        score = max(score, sld_sim * 0.8)
        # substring/token boosts
        if sim_sub >= thresholds['substring_ratio']:
            score = max(score, 0.6 + (sim_sub - thresholds['substring_ratio']) * 0.4)
        if token_sim >= 0.5:
            # tokens overlap is suspicious
            score = max(score, 0.5 + token_sim * 0.4)

        # if TLD changed (e.g., example.com -> example.co) and sld same -> increase
        if sld_a == sld_b and tld_a != tld_b:
            score = max(score, 0.7)

        # length ratio extremes
        len_ratio = min(len(a), len(b)) / max(1, max(len(a), len(b)))
        if len_ratio < thresholds['length_ratio_extreme']:
            score = max(score, 0.5)

        # aggregate best match
        if score > highest_score:
            highest_score = score
            matched_legit = ld

        # add targeted reasons when thresholds crossed
        if sim_full >= thresholds['edit_distance_ratio_block'] or sld_sim >= thresholds['edit_distance_ratio_block']:
            reasons.append(f"High edit similarity ({sim_full:.2f}) to trusted domain '{ld}'.")
        elif sim_full >= thresholds['edit_distance_ratio_warn'] or sld_sim >= thresholds['edit_distance_ratio_warn']:
            reasons.append(f"Moderate edit similarity ({sim_full:.2f}) to trusted domain '{ld}'.")

    # Additional heuristic: suspicious separators or digits inside domain that mimic letters (examp1e)
    if re.search(r'\d', domain):
        reasons.append("Digits present in domain (e.g., '1' vs 'l') — common typosquatting trick.")
        highest_score = max(highest_score, 0.55)

    # if it contains the legit SLD but with extra prefix like 'secure-login-example.com'
    for L in legit_domains:
        ld = normalize_domain(L)
        if ld.split('.')[0] in domain and domain != ld:
            reasons.append(f"Contains legit name fragment '{ld.split('.')[0]}' embedded.")
            highest_score = max(highest_score, 0.6)

    # Final decision mapping
    action = "allow"
    if highest_score >= thresholds['edit_distance_ratio_block'] or highest_score >= 0.9:
        action = "block"
        reasons.append(f"Score {highest_score:.2f} >= block threshold.")
    elif highest_score >= thresholds['edit_distance_ratio_warn'] or highest_score >= 0.75:
        action = "warn"
        reasons.append(f"Score {highest_score:.2f} >= warn threshold.")

    if not reasons:
        reasons.append("No strong signs of typosquatting detected.")

    return round(highest_score, 3), reasons, action

# ---------- Integration example: Flask middleware ----------
# Usage: In your Flask app, register check_request_domain as before_request handler
def flask_before_request_check(app, legit_domains: List[str], thresholds: Dict[str, float] = None):
    """
    Example integration function that attaches a before_request hook to app.
    It checks the Host header and Referer (if provided) to detect suspicious domains.
    """
    from flask import request, abort, make_response

    @app.before_request
    def _check():
        host = request.host.split(':')[0] if request.host else ''
        referer = request.headers.get('Referer', '') or request.headers.get('Referrer', '')
        # Optionally check referer and any submitted URLs in form data
        # Evaluate host first
        score, reasons, action = is_domain_suspicious(host, legit_domains, thresholds)
        if action == "block":
            # log details, then return an error or block page
            app.logger.warning(f"Blocked request to host {host}. Reasons: {reasons}")
            return make_response("Access blocked (suspicious domain).", 403)
        elif action == "warn":
            # you may want to set a header or a cookie, or redirect to interstitial
            app.logger.info(f"Warning for host {host}. Reasons: {reasons}")
            # Example: set a response header to indicate detection (downstream logic can use)
            # Note: in before_request we don't have response yet. You could attach to g.
            from flask import g
            g.typosquat_warning = {"host": host, "score": score, "reasons": reasons}
        # else allow
        return None

# ---------- Simple CLI / test harness ----------
if __name__ == "__main__":
    # quick test
    test_legit = [
        "example.com",
        "mycompany.com",
        "secure-bank.com",
        "github.com"
    ]
    tests = [
        "examp1e.com",
        "example.co",
        "xn--exmple-9ua.com",  # punycode-like
        "examp.le.com",
        "secure-login-mycompany.com",
        "githb.com",
        "gïthub.com",  # unicode homoglyph
        "example.com",  # exact
        "randomsite.org"
    ]
    for t in tests:
        score, reasons, action = is_domain_suspicious(t, test_legit)
        print(f"{t:30} -> score={score:.3f} action={action} reasons={reasons}")
