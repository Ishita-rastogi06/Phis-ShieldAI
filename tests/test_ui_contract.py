"""Static contracts for the shared Streamlit URL-result renderer."""
from pathlib import Path
import unittest


class UrlResultUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = (Path(__file__).parents[1] / "app.py").read_text(encoding="utf-8")
        cls.renderer = cls.app.split('def render_url_evidence(result, scan_type="URL"):', 1)[1].split('\ndef _risk_chip', 1)[0]

    def test_one_common_action_row_uses_canonical_report(self):
        self.assertEqual(self.renderer.count('download_button('), 1)
        self.assertIn('generate_pdf_report(scan_type, result)', self.renderer)

    def test_verdict_precedes_tabs(self):
        self.assertLess(self.renderer.index('FINAL VERDICT'), self.renderer.index('st.tabs('))

    def test_affected_tabs_do_not_use_raw_json_widgets(self):
        self.assertNotIn('st.json(', self.renderer)
        for heading in ('DOMAIN & TLD STRUCTURE ANALYSIS', 'TLS & HTTPS SECURITY CERTIFICATE', 'DNS RECORDS INTELLIGENCE', 'WHOIS & RDAP DOMAIN REGISTRATION INTELLIGENCE'):
            self.assertIn(heading, self.renderer)

    def test_unavailable_statuses_are_preserved_in_cards(self):
        self.assertIn('UNAVAILABLE_STATUSES', self.app)
        self.assertIn('source-unavailable', self.app)

    def test_direct_and_qr_routes_do_not_require_legacy_ml_confidence(self):
        # The renderer receives a normalized canonical result.  Direct/QR
        # routes must not index optional legacy telemetry before rendering it.
        self.assertNotIn('prediction_data["confidence"]', self.app)
