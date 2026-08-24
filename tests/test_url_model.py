import unittest
from feature_extractor import FeatureUnavailableError, extract_features, extract_live_features, extract_live_feature_mapping

class LiveModelTests(unittest.TestCase):
    def test_legacy_30_feature_raises_unavailable(self):
        with self.assertRaises(FeatureUnavailableError):
            extract_features("https://example.com")

    def test_live_25_feature_extraction(self):
        mapping = extract_live_feature_mapping("https://example.com")
        self.assertEqual(len(mapping), 25)
        feats = extract_live_features("https://example.com")
        self.assertEqual(len(feats), 25)

    def test_live_ml_prediction(self):
        from ml.url_detector import predict_url
        res = predict_url("https://wikipedia.org")
        self.assertTrue(res["model_available"])
        self.assertIn(res["prediction"], (0, 1))
        self.assertGreaterEqual(res["confidence"], 0.0)

    def test_pipeline_runs_live_ml(self):
        from unittest.mock import patch
        from analysis.url_analysis_pipeline import analyze_url
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value="https://example.com"), patch("analysis.url_analysis_pipeline.collect_remote", return_value={}), patch("analysis.url_analysis_pipeline.analyze_website", return_value={"reachable": True, "title": "Example", "forms": [], "iframes": 0}), patch("analysis.url_analysis_pipeline.inspect_tls", return_value={"https": True, "connected": True, "certificate_valid": True}), patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "RESOLVED"}), patch("analysis.url_analysis_pipeline.check_domain_age", return_value={"status": "AVAILABLE", "age_days": 1000}):
            result = analyze_url("https://example.com")
        self.assertTrue(result["model_available"])
        self.assertEqual(result["verdict"], "LIKELY_LEGITIMATE")

    def test_known_phishing_url_pipeline_verdict(self):
        from unittest.mock import patch
        from analysis.url_analysis_pipeline import analyze_url
        provider = {"openphish": {"provider": "openphish", "status": "AVAILABLE", "malicious": True, "strong": True, "evidence": {}, "reason": "match"}}
        with patch("analysis.url_analysis_pipeline.normalise_url", return_value="https://bad.example/login"), patch("analysis.url_analysis_pipeline.collect_remote", return_value=provider), patch("analysis.url_analysis_pipeline.analyze_website", return_value={"reachable": True, "title": "Login", "forms": [{}], "iframes": 0}), patch("analysis.url_analysis_pipeline.inspect_tls", return_value={"https": True, "connected": True, "certificate_valid": True}), patch("analysis.url_analysis_pipeline.analyze_dns", return_value={"status": "RESOLVED"}), patch("analysis.url_analysis_pipeline.check_domain_age", return_value={"status": "AVAILABLE", "age_days": 5}):
            result = analyze_url("https://bad.example/login")
        self.assertEqual(result["verdict"], "LIKELY_PHISHING")
