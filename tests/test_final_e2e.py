"""Deterministic end-to-end policy tests; no live malicious URLs are used."""
import unittest
from unittest.mock import patch

from intelligence.contracts import AVAILABLE, NO_MATCH, TIMEOUT, UNAVAILABLE, result


class CanonicalE2ETests(unittest.TestCase):
    def _scan(self, url, providers, website, tls, whois):
        from analysis.url_analysis_pipeline import analyze_url
        model = {"model_available": False, "prediction": None, "confidence": None,
                 "error": "historical features unavailable"}
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value=url), \
             patch("analysis.url_analysis_pipeline.collect_remote", return_value=providers), \
             patch("analysis.url_analysis_pipeline.predict_url", return_value=model), \
             patch("analysis.url_analysis_pipeline.analyze_website", return_value=website), \
             patch("analysis.url_analysis_pipeline.inspect_tls", return_value=tls), \
             patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "RESOLVED", "a_records": ["93.184.216.34"]}), \
             patch("analysis.url_analysis_pipeline.check_domain_age", return_value=whois):
            return analyze_url(url)

    def test_legitimate_e2e_has_affirmative_evidence_not_no_match_safety(self):
        providers = {name: result(name, NO_MATCH, reason="No record") for name in ("virustotal", "urlscan", "urlhaus", "openphish")}
        scan = self._scan("https://example.com", providers,
                          {"reachable": True, "title": "Example", "forms": [], "iframes": 0},
                          {"https": True, "connected": True, "certificate_valid": True},
                          {"status": AVAILABLE, "age_days": 1000})
        self.assertEqual(scan["verdict"], "LIKELY_LEGITIMATE")
        self.assertEqual((scan["brand"], scan["mitre"]), ("Unknown", []))
        self.assertEqual(scan["provider_statuses"]["virustotal"], NO_MATCH)

    def test_phishing_e2e_vt_consensus_is_confirmed_and_evidence_grounded(self):
        providers = {"virustotal": result("virustotal", AVAILABLE, evidence={"malicious": 5}, malicious=True, strong=True),
                     "urlscan": result("urlscan", NO_MATCH), "urlhaus": result("urlhaus", NO_MATCH), "openphish": result("openphish", NO_MATCH)}
        scan = self._scan("https://bad.example/login", providers,
                          {"reachable": True, "title": "Account login", "forms": [{"action": "/submit"}], "iframes": 0},
                          {"https": True, "connected": True, "certificate_valid": True},
                          {"status": AVAILABLE, "age_days": 5})
        self.assertEqual(scan["verdict"], "CONFIRMED_MALICIOUS")
        self.assertGreaterEqual(scan["risk"], 85)
        self.assertTrue(any(item["id"] == "T1566.002" for item in scan["mitre"]))
        self.assertIn("VirusTotal", " ".join(scan["reasons"]))

    def test_suspicious_e2e_no_match_is_not_legitimate(self):
        providers = {name: result(name, NO_MATCH) for name in ("virustotal", "urlscan", "urlhaus", "openphish")}
        scan = self._scan("https://amaz0n-security-alert.com/login", providers,
                          {"reachable": True, "title": "Login", "forms": [{"action": "/login"}], "iframes": 0},
                          {"https": True, "connected": True, "certificate_valid": True},
                          {"status": AVAILABLE, "age_days": 5})
        self.assertEqual(scan["verdict"], "SUSPICIOUS")
        self.assertNotEqual(scan["verdict"], "LIKELY_LEGITIMATE")

    def test_insufficient_e2e_preserves_each_unavailable_status(self):
        providers = {"virustotal": result("virustotal", TIMEOUT, reason="timeout"),
                     "urlscan": result("urlscan", UNAVAILABLE, reason="offline"),
                     "urlhaus": result("urlhaus", UNAVAILABLE, reason="offline"),
                     "openphish": result("openphish", UNAVAILABLE, reason="offline")}
        scan = self._scan("https://example.com", providers,
                          {"reachable": False, "title": None, "forms": [], "iframes": 0},
                          {"https": True, "connected": False, "certificate_valid": False},
                          {"status": UNAVAILABLE})
        self.assertEqual(scan["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(scan["provider_statuses"]["virustotal"], TIMEOUT)
        self.assertIn("Insufficient live evidence", scan["ai_copilot"]["strategy"])

    def test_extracted_url_batch_is_deduplicated_before_canonical_routing(self):
        from analysis.input_routes import analyze_extracted_urls
        urls = ["https://one.example", "https://two.example"]
        with patch("analysis.input_routes.analyze_url", side_effect=lambda value: {"url": value, "normalized_url": value}) as analyzer:
            outcomes = analyze_extracted_urls(urls)
        self.assertEqual([item["normalized_url"] for item in outcomes], urls)
        self.assertEqual(analyzer.call_count, 2)

    def test_blocked_result_normalizes_optional_legacy_confidence_for_ui(self):
        """Regression: SSRF/unresolved outcomes must not omit ML telemetry keys."""
        from analysis.url_analysis_pipeline import analyze_url
        scan = analyze_url("http://127.0.0.1")
        self.assertEqual(scan["final_verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("confidence", scan["model"])
        self.assertIsNone(scan["model"]["confidence"])
        self.assertEqual(set(scan["providers"]), {"virustotal", "urlscan", "urlhaus", "openphish"})

    def test_ocr_and_email_extraction_multi_url_markdown_deduplicates(self):
        from security.url_extraction import extract_urls
        text = "[one](https://one.example/a), www.two.example/b! https://one.example/a"
        self.assertEqual(extract_urls(text), ["https://one.example/a", "https://www.two.example/b"])
