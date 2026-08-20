import unittest
from feature_extractor import FeatureUnavailableError, extract_features

class LegacyModelTests(unittest.TestCase):
    def test_feature_extraction_emits_30_features(self):
        features = extract_features("https://example.com")
        self.assertEqual(len(features), 30)
        self.assertTrue(all(isinstance(v, int) for v in features))
    def test_pipeline_keeps_working_when_legacy_ml_is_unavailable(self):
        from unittest.mock import patch
        from analysis.url_analysis_pipeline import analyze_url
        mock_model = {"model_available": False, "prediction": None, "confidence": None, "error": "legacy model unavailable"}
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value="https://example.com"), patch("analysis.url_analysis_pipeline.predict_url", return_value=mock_model), patch("analysis.url_analysis_pipeline.collect_remote", return_value={}), patch("analysis.url_analysis_pipeline.analyze_website", return_value={"reachable": False, "title": None, "forms": [], "iframes": 0}), patch("analysis.url_analysis_pipeline.inspect_tls", return_value={"https": True, "connected": False, "certificate_valid": False}), patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "UNAVAILABLE"}), patch("analysis.url_analysis_pipeline.check_domain_age", return_value={"status": "UNAVAILABLE"}):
            result = analyze_url("https://example.com")
        self.assertFalse(result["model_available"]); self.assertIn(result["verdict"], {"SUSPICIOUS", "INSUFFICIENT_EVIDENCE"})
    def test_known_legitimate_url_pipeline_verdict(self):
        from unittest.mock import patch
        from analysis.url_analysis_pipeline import analyze_url
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value="https://example.com"), patch("analysis.url_analysis_pipeline.collect_remote", return_value={}), patch("analysis.url_analysis_pipeline.analyze_website", return_value={"reachable": True, "title": "Example", "forms": [], "iframes": 0}), patch("analysis.url_analysis_pipeline.inspect_tls", return_value={"https": True, "connected": True, "certificate_valid": True}), patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "RESOLVED"}), patch("analysis.url_analysis_pipeline.check_domain_age", return_value={"status": "AVAILABLE", "age_days": 1000}):
            result = analyze_url("https://example.com")
        self.assertEqual(result["verdict"], "LIKELY_LEGITIMATE")
    def test_known_phishing_url_pipeline_verdict(self):
        from unittest.mock import patch
        from analysis.url_analysis_pipeline import analyze_url
        provider = {"openphish": {"provider": "openphish", "status": "AVAILABLE", "malicious": True, "strong": True, "evidence": {}, "reason": "match"}}
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value="https://bad.example/login"), patch("analysis.url_analysis_pipeline.collect_remote", return_value=provider), patch("analysis.url_analysis_pipeline.analyze_website", return_value={"reachable": True, "title": "Login", "forms": [{}], "iframes": 0}), patch("analysis.url_analysis_pipeline.inspect_tls", return_value={"https": True, "connected": True, "certificate_valid": True}), patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "RESOLVED"}), patch("analysis.url_analysis_pipeline.check_domain_age", return_value={"status": "AVAILABLE", "age_days": 5}):
            result = analyze_url("https://bad.example/login")
        # A feed match corroborated by local indicators is strong phishing
        # evidence, but not an independently confirmed malware record.
        self.assertEqual(result["verdict"], "LIKELY_PHISHING")
