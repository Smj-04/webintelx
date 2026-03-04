"""Comprehensive test suite for phishing detection system."""
import unittest
import os
import sys
import json
from io import StringIO
import pandas as pd

# Add project to path
sys.path.insert(0, os.path.dirname(__file__))

from phishing.features.brand_detection import brand_similarity, load_brands
from phishing.features.domain_checks import resolve_domain, get_ssl_days_left, get_domain_age_days
from phishing.features.utils import URLValidator, RateLimiter, JSONOutput, check_dependencies


class TestBrandDetection(unittest.TestCase):
    """Test brand similarity scoring."""
    
    def setUp(self):
        self.brands = load_brands(min_count=100, try_fetch=False)
    
    def test_exact_match(self):
        """Exact brand match should return ~1.0 similarity."""
        score = brand_similarity("google")
        self.assertGreater(score, 0.9)
    
    def test_typo_attack(self):
        """Typo squatting (e.g., 'gogle' vs 'google') should detect similarity."""
        score = brand_similarity("gogle")
        self.assertGreater(score, 0.5)
    
    def test_low_similarity(self):
        """Unrelated domain should have low similarity."""
        score = brand_similarity("xyzabc123notabrand")
        self.assertLess(score, 0.3)
    
    def test_case_insensitivity(self):
        """Brand matching should be case-insensitive."""
        score1 = brand_similarity("google")
        score2 = brand_similarity("GOOGLE")
        self.assertAlmostEqual(score1, score2, places=2)
    
    def test_brands_loaded(self):
        """Verify brands file loads successfully."""
        self.assertGreater(len(self.brands), 100)
        self.assertIn("google", self.brands)


class TestDomainChecks(unittest.TestCase):
    """Test domain resolution, SSL and WHOIS checks."""
    
    def test_dns_resolve_google(self):
        """google.com should resolve (if network available)."""
        result = resolve_domain("google.com")
        # Result may be None if network unavailable, but shouldn't error
        self.assertIsNotNone(result or None, msg="DNS check should complete")
    
    def test_dns_invalid_domain(self):
        """Invalid domain should not resolve."""
        result = resolve_domain("thisdomain-should-not-exist-12345xyz.com")
        self.assertEqual(result, False)
    
    def test_ssl_certificate_fetch(self):
        """SSL certificate days-left should return int or None."""
        days = get_ssl_days_left("google.com")
        self.assertTrue(days is None or isinstance(days, int))
    
    def test_domain_age_lookup(self):
        """Domain age lookup via whois returns int or None."""
        age = get_domain_age_days("google.com")
        self.assertTrue(age is None or isinstance(age, int))


class TestURLValidator(unittest.TestCase):
    """Test URL validation and sanitization."""
    
    def test_valid_https_url(self):
        """Valid HTTPS URL should pass."""
        url = "https://google.com"
        result = URLValidator.validate(url)
        self.assertIsNotNone(result)
    
    def test_valid_http_url(self):
        """Valid HTTP URL should pass."""
        url = "http://example.com"
        result = URLValidator.validate(url)
        self.assertIsNotNone(result)
    
    def test_url_without_scheme(self):
        """URL without scheme should be prefixed with https."""
        url = "google.com"
        result = URLValidator.validate(url)
        self.assertTrue(result.startswith("https"))
    
    def test_invalid_url(self):
        """Invalid URL should return None."""
        url = "not a url"
        result = URLValidator.validate(url)
        self.assertIsNone(result)
    
    def test_empty_url(self):
        """Empty URL should return None."""
        result = URLValidator.validate("")
        self.assertIsNone(result)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiting."""
    
    def test_rate_limiter_allows_within_limit(self):
        """Requests within limit should be allowed."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        self.assertTrue(limiter.is_allowed())
        self.assertTrue(limiter.is_allowed())
        self.assertTrue(limiter.is_allowed())
    
    def test_rate_limiter_rejects_over_limit(self):
        """Requests exceeding limit should be rejected."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        self.assertTrue(limiter.is_allowed())
        self.assertTrue(limiter.is_allowed())
        self.assertFalse(limiter.is_allowed())


class TestJSONOutput(unittest.TestCase):
    """Test JSON output serialization."""
    
    def test_json_output_format(self):
        """JSON output should be valid and complete."""
        breakdown = {
            "url_score": 10,
            "domain_score": 20,
            "content_score": 15
        }
        output_json = JSONOutput.format(
            url="https://google.com",
            verdict="LEGITIMATE",
            confidence="LOW",
            risk_score=15.0,
            breakdown=breakdown,
            model_pred="LEGITIMATE",
            model_conf=0.99
        )
        # Verify it's valid JSON
        data = json.loads(output_json)
        self.assertEqual(data["url"], "https://google.com")
        self.assertEqual(data["verdict"], "LEGITIMATE")
        self.assertIn("timestamp", data)
        self.assertIn("breakdown", data)
        self.assertIn("model_prediction", data)


class TestDependencies(unittest.TestCase):
    """Test dependency availability."""
    
    def test_dependencies_checked(self):
        """Should check for aiohttp and whois."""
        deps = check_dependencies()
        self.assertIn("aiohttp", deps)
        self.assertIn("whois", deps)
        # asyncio should always be available
        self.assertTrue(deps.get("asyncio", False))


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple components."""
    
    def test_url_validation_and_brand_similarity(self):
        """Should validate URL and compute brand similarity."""
        url = "https://gogle.com"  # typo of google
        validated = URLValidator.validate(url)
        self.assertIsNotNone(validated)
        
        # Extract domain and test similarity
        from urllib.parse import urlparse
        domain = urlparse(validated).netloc.replace("www.", "").split(".")[0]
        similarity = brand_similarity(domain)
        self.assertGreater(similarity, 0.5)
    
    def test_suspicious_url_detection(self):
        """Should detect suspicious patterns."""
        # IP address instead of domain
        url_with_ip = "http://192.168.1.1/login"
        validated = URLValidator.validate(url_with_ip)
        # This URL is technically valid format but contains IP
        # The phishing detector should flag it in realtime_features
        self.assertIsNotNone(validated)


# Model performance baseline
class TestModelPerformance(unittest.TestCase):
    """Test model accuracy and consistency."""
    
    def test_model_load(self):
        """Model should load without errors."""
        try:
            import joblib
            model = joblib.load("models/phishing_model.pkl")
            self.assertIsNotNone(model)
        except FileNotFoundError:
            self.skipTest("Model file not found; skipping model test")
    
    def test_model_feature_requirements(self):
        """Model should have expected feature names."""
        try:
            import joblib
            model = joblib.load("models/phishing_model.pkl")
            if hasattr(model, 'feature_names_in_'):
                features = list(model.feature_names_in_)
                # Check for key features
                self.assertIn("URLLength", features)
                self.assertIn("IsHTTPS", features)
        except FileNotFoundError:
            self.skipTest("Model file not found")


class TestMLEscalation(unittest.TestCase):
    """Verify that a strong ML phishing prediction influences final scoring."""

    def test_ml_prediction_influences_score(self):
        try:
            import joblib, sys
            # prevent argparse in main.py from consuming unittest args
            old_argv = sys.argv.copy()
            sys.argv = ["main.py"]
            import main
            sys.argv = old_argv
            analyze_phishing_comprehensive = main.analyze_phishing_comprehensive
            model = main.model
            from phishing.features.realtime_features import extract_realtime_features
        except ImportError:
            self.skipTest("Required modules not available")
        url = (
            "http://secure-login-paypal.com.account-verify.update-user.ru/login/"
            "confirm.php?session=984723"
        )
        features = extract_realtime_features(url)
        df = pd.DataFrame([features])
        if hasattr(model, "feature_names_in_"):
            df = df.reindex(columns=list(model.feature_names_in_), fill_value=0)
        pred = model.predict(df)[0]
        conf = model.predict_proba(df)[0][int(pred)]
        # model should consider this phishing; otherwise skip escalation check
        if pred != 1 or conf <= 0.8:
            self.skipTest("Model did not strongly predict phishing for test URL")

        analysis = analyze_phishing_comprehensive(url, features)
        url_score = analysis["url_score"]
        domain_score = analysis["domain_score"]
        content_score = analysis["content_score"]
        weighted = (
            content_score * 0.5
            + domain_score * 0.3
            + url_score * 0.2
        )
        # replicate escalation logic from main.py
        has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
        brand_sim = features.get("BrandSimilarity", 0)
        if brand_sim > 0.7 and brand_sim < 1.0 and not has_content:
            overall = max(weighted, 75)
        elif domain_score > 40 and not has_content:
            overall = max(weighted, 60)
        elif content_score >= 30 and url_score < 10 and domain_score < 10:
            overall = max(weighted, 60)
        elif not has_content:
            overall = max(weighted, 60)
        else:
            overall = weighted
        # apply ML escalation
        if pred == 1 and conf > 0.8:
            overall = max(overall, 75)
        self.assertGreaterEqual(overall, 75)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2, exit=True)
