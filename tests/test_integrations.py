import unittest
from unittest.mock import patch, Mock
from analysis.risk_engine import calculate_verdict
from history_manager import clear_history, load_history, save_scan
from report_generator import generate_report
from security.url_extraction import extract_urls
from security.url_security import UnsafeURLError, normalise_url
from intelligence.contracts import result, AVAILABLE, NO_MATCH, NOT_CONFIGURED, RATE_LIMITED, TIMEOUT, UNAVAILABLE

class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        from intelligence.provider_cache import cache_clear
        cache_clear()
    def tearDown(self):
        clear_history()
        from intelligence.provider_cache import cache_clear
        cache_clear()
    def test_url_extraction_normalises_and_deduplicates(self):
        self.assertEqual(extract_urls("www.example.com/a https://example.com/a https://example.com/a"), ["https://www.example.com/a", "https://example.com/a"])
    @patch("virustotal_scanner.requests.get")
    @patch("virustotal_scanner.os.getenv", return_value="key")
    def test_virustotal_malicious_and_no_match(self, _key, get):
        from virustotal_scanner import lookup_url_virustotal
        get.return_value = Mock(status_code=200, json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 0}}}}); get.return_value.raise_for_status = Mock()
        self.assertTrue(lookup_url_virustotal("https://example.com")["strong"])
        from intelligence.provider_cache import cache_clear; cache_clear()
        get.return_value.status_code = 404; self.assertEqual(lookup_url_virustotal("https://example.com")["status"], "NO_MATCH")
    @patch("intelligence.openphish._feed", return_value={"https://bad.example"})
    def test_openphish_hit(self, _feed):
        from intelligence.openphish import lookup_url
        self.assertTrue(lookup_url("https://bad.example")["malicious"])
    def test_verdict_policy(self):
        self.assertEqual(calculate_verdict(providers={}, brand_similarity=95, trusted_domain=False, website={"forms": [{}]}, tls={}, whois=None, local_reasons=["credential login"])[0], "LIKELY_PHISHING")
        self.assertEqual(calculate_verdict(providers={}, brand_similarity=0, trusted_domain=False, website={}, tls={}, whois=None, local_reasons=[])[0], "INSUFFICIENT_EVIDENCE")
    def test_ssrf_is_blocked(self):
        for target in ("http://127.0.0.1", "http://localhost", "http://[::1]", "http://169.254.1.1"):
            with self.assertRaises(UnsafeURLError): normalise_url(target)
    def test_brand_fixes(self):
        from brand_detector import detect_brand
        from mitre_mapper import map_to_mitre
        for domain in ("example.com", "google.com", "amazon.com", "apple.com"):
            self.assertEqual(detect_brand("https://" + domain)[0], "Unknown")
            self.assertEqual(map_to_mitre("https://" + domain, 0, 10, [], {"iframes": 1}), [])
        self.assertEqual(detect_brand("https://amaz0n-security-alert.com")[0], "amazon")
    def test_history_and_report_preserve_evidence(self):
        save_scan("URL", "https://example.com", "INSUFFICIENT_EVIDENCE", 0, providers={"virustotal": {"status": "NO_MATCH"}})
        self.assertIn("Provider Evidence", load_history().columns)
        self.assertIn("Normalized provider evidence", generate_report("https://example.com", "INSUFFICIENT_EVIDENCE", 0, "test", providers={"virustotal": {"status": "NO_MATCH"}}))
    def test_canonical_history_and_report_include_local_evidence(self):
        from history_manager import save_canonical_scan
        from report_generator import generate_canonical_report
        analysis = {"url": "https://example.com", "normalized_url": "https://example.com", "verdict": "INSUFFICIENT_EVIDENCE", "risk": 0,
                    "confidence_strength": "insufficient", "risk_level": "INSUFFICIENT_EVIDENCE", "reasons": ["test"], "providers": {"openphish": result("openphish", NO_MATCH)},
                    "dns": {"status": "RESOLVED"}, "tls": {"certificate_valid": True}, "whois": {"status": "AVAILABLE"}, "website": {"reachable": True, "html": "omit"},
                    "brand": "Unknown", "similarity": 0, "mitre": [], "ai_copilot": {"engine": "deterministic evidence copilot"}, "model_available": False, "virustotal": None, "recommendation": "review"}
        save_canonical_scan("URL", analysis)
        row = load_history().iloc[0]
        self.assertEqual(row["Normalized URL"], "https://example.com")
        self.assertIn("certificate_valid", row["Local Evidence"])
        self.assertIn("Website analysis", generate_canonical_report("URL", analysis))
    def test_no_match_is_not_legitimate(self):
        verdict = calculate_verdict(providers={"virustotal": result("virustotal", NO_MATCH)}, brand_similarity=0, trusted_domain=False, website={}, tls={}, whois=None, local_reasons=[])[0]
        self.assertEqual(verdict, "INSUFFICIENT_EVIDENCE")
    def test_single_vt_flag_does_not_erase_strong_local_legitimacy(self):
        providers = {"virustotal": result("virustotal", AVAILABLE, evidence={"malicious": 1, "harmless": 64}, malicious=True),
                     "openphish": result("openphish", TIMEOUT)}
        verdict, risk, _, _ = calculate_verdict(providers=providers, brand_similarity=0, trusted_domain=True,
            website={"reachable": True}, tls={"certificate_valid": True}, dns={"status": "RESOLVED", "a_records": ["8.8.8.8"]},
            whois=None, local_reasons=[])
        self.assertEqual((verdict, risk), ("LIKELY_LEGITIMATE", 10))
    def test_unavailable_provider_is_not_safety_evidence(self):
        verdict, risk, _, _ = calculate_verdict(providers={"openphish": result("openphish", UNAVAILABLE)}, brand_similarity=0, trusted_domain=False, website={}, tls={}, whois=None, local_reasons=[])
        self.assertEqual((verdict, risk), ("INSUFFICIENT_EVIDENCE", 0))
    def test_all_providers_unavailable_is_insufficient_evidence(self):
        providers = {name: result(name, UNAVAILABLE) for name in ("virustotal", "openphish")}
        self.assertEqual(calculate_verdict(providers=providers, brand_similarity=0, trusted_domain=False, website={}, tls={}, whois=None, local_reasons=[])[0], "INSUFFICIENT_EVIDENCE")
    @patch("intelligence.openphish._feed", side_effect=__import__('requests').Timeout())
    def test_openphish_timeout_and_unavailable(self, _feed):
        from intelligence.openphish import lookup_url
        self.assertEqual(lookup_url("https://example.com")["status"], TIMEOUT)
    @patch("intelligence.openphish._feed", side_effect=__import__('requests').RequestException("offline"))
    def test_openphish_unavailable(self, _feed):
        from intelligence.openphish import lookup_url
        self.assertEqual(lookup_url("https://example.com")["status"], UNAVAILABLE)
    @patch("virustotal_scanner.os.getenv", return_value="")
    def test_virustotal_not_configured(self, _key):
        from virustotal_scanner import lookup_url_virustotal
        self.assertEqual(lookup_url_virustotal("https://example.com")["status"], NOT_CONFIGURED)
    @patch("virustotal_scanner.requests.get", side_effect=__import__('requests').Timeout())
    @patch("virustotal_scanner.os.getenv", return_value="key")
    def test_virustotal_timeout(self, _key, _get):
        from virustotal_scanner import lookup_url_virustotal
        self.assertEqual(lookup_url_virustotal("https://example.com")["status"], TIMEOUT)
    def test_environment_variable_names_are_consumed(self):
        from pathlib import Path
        source = Path("virustotal_scanner.py").read_text(encoding="utf-8")
        self.assertIn("VIRUSTOTAL_API_KEY", source)
    @patch("dns_intelligence.dns.resolver.Resolver.resolve")
    def test_dns_records(self, resolve):
        from dns_intelligence import analyze_dns
        analyze_dns.cache_clear(); resolve.return_value = ["1.2.3.4"]
        self.assertEqual(analyze_dns("https://example.com")["status"], "RESOLVED")
    @patch("tls_intelligence.socket.create_connection", side_effect=__import__('socket').timeout())
    def test_tls_timeout_is_explicit(self, _connect):
        from tls_intelligence import inspect_tls
        inspect_tls.cache_clear(); self.assertFalse(inspect_tls("https://example.com")["certificate_valid"])
    @patch("whois_checker.whois.whois", side_effect=TimeoutError("offline"))
    @patch("whois_checker.requests.get", side_effect=__import__('requests').Timeout())
    def test_whois_timeout_stays_unavailable(self, _rdap, _whois):
        from whois_checker import check_domain_age
        check_domain_age.cache_clear(); self.assertEqual(check_domain_age("https://example.com")["status"], UNAVAILABLE)
    @patch("website_analyzer.requests.get")
    def test_redirect_to_private_target_is_blocked(self, get):
        from website_analyzer import analyze_website
        analyze_website.cache_clear(); get.return_value = Mock(is_redirect=True, headers={"Location": "http://127.0.0.1"}, url="https://example.com")
        self.assertIn("private", (analyze_website("https://example.com")["error"] or "").lower())
    def test_ui_contract_and_canonical_routes(self):
        from pathlib import Path
        source = Path("app.py").read_text(encoding="utf-8")
        for label in ("FINAL VERDICT", "Risk score", "Why this verdict", "Provider Evidence", "DNS", "TLS", "WHOIS", "Website", "VirusTotal", "MITRE"):
            self.assertIn(label, source)
        self.assertGreaterEqual(source.count("run_complete_url_analysis("), 2)
        self.assertIn("analyze_extracted_urls", source)
        self.assertIn("--cream", source); self.assertIn("--espresso", source); self.assertIn("stDownloadButton", source)
    def test_qr_duplicate_risk_code_cannot_execute(self):
        from pathlib import Path
        source = Path("app.py").read_text(encoding="utf-8")
        qr_route = source.split('if analysis_mode == "QR Analysis":', 1)[1]
        first_render = qr_route.index('render_url_evidence(complete_url_result, scan_type="QR")')
        self.assertNotIn('prediction_data["confidence"]', qr_route[:first_render])
    def test_dataset_is_not_a_runtime_dependency(self):
        from pathlib import Path
        runtime = "\n".join(Path(p).read_text(encoding="utf-8") for p in ("app.py", "analysis/url_analysis_pipeline.py", "ml/url_detector.py", "feature_extractor.py"))
        self.assertNotIn("dataset.csv", runtime)
    def test_all_providers_are_wired_to_shared_pipeline(self):
        from pathlib import Path
        source = Path("analysis/url_analysis_pipeline.py").read_text(encoding="utf-8")
        manager = Path("intelligence/provider_manager.py").read_text(encoding="utf-8")
        self.assertIn("collect_remote", source)
        for name in ("virustotal", "openphish"): self.assertIn(name, manager)
    def test_pipeline_is_bounded_and_concurrent(self):
        from pathlib import Path
        source = Path("analysis/url_analysis_pipeline.py").read_text(encoding="utf-8")
        self.assertIn("ThreadPoolExecutor", source); self.assertIn("SOURCE_TIMEOUT = 10.0", source); self.assertIn("shutdown(wait=False", source)
    def test_qr_screenshot_and_email_canonical_url_paths(self):
        from email_url_scanner import extract_urls as email_urls
        from security.url_extraction import extract_urls
        urls = extract_urls("https://one.example/a www.two.example/b https://one.example/a")
        self.assertEqual(len(urls), 2)
        self.assertEqual(email_urls("https://one.example/a https://two.example/b"), ["https://one.example/a", "https://two.example/b"])
    @patch("qr_analyzer.cv2.imread", return_value=object())
    @patch("qr_analyzer.cv2.QRCodeDetector")
    def test_qr_url_decode(self, detector_class, _read):
        from qr_analyzer import analyze_qr
        detector_class.return_value.detectAndDecode.return_value = ("https://one.example/a", None, None)
        self.assertEqual(analyze_qr("ignored.png"), "https://one.example/a")
