import os
import tempfile
import unittest
from unittest.mock import patch

import dns.resolver

_TEMP_DIRECTORY = tempfile.TemporaryDirectory()
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault(
    "DANGLESCAN_DB_PATH",
    os.path.join(_TEMP_DIRECTORY.name, "dns-logic.db"),
)

import main


class _CnameRecord:
    def __init__(self, target: str):
        self.target = target


class _FakeResolver:
    timeout = 3
    lifetime = 3

    def resolve(self, name: str, record_type: str):
        key = (name.rstrip("."), record_type)
        responses = {
            ("sip.example.com", "CNAME"): [_CnameRecord("missing.vendor.example.")],
        }
        if key in responses:
            return responses[key]
        if name.rstrip(".") == "missing.vendor.example":
            raise dns.resolver.NXDOMAIN
        raise dns.resolver.NoAnswer


class DnsClassificationTests(unittest.TestCase):
    @patch("main.dns.resolver.Resolver", return_value=_FakeResolver())
    def test_explicit_cname_target_nxdomain_is_dangling(self, _resolver):
        dns_info = main.resolve_dns("sip.example.com")
        analysis = main.rule_based_analysis(
            "sip.example.com",
            dns_info,
            {"body_snippet": ""},
        )

        self.assertFalse(dns_info["nxdomain"])
        self.assertTrue(dns_info["cname_target_nxdomain"])
        self.assertEqual(dns_info["resolution_status"], "CNAME target NXDOMAIN")
        self.assertEqual(analysis["verdict"], "dangling_dns")
        self.assertEqual(analysis["severity"], "high")
        self.assertEqual(analysis["confidence"], 85)

    def test_unrelated_external_redirect_is_high(self):
        analysis = main.rule_based_analysis(
            "readerspoll.pitchfork.com",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://rez.onfan.co/tubex/?readerspoll.pitchfork.com",
                "title": "Security Clearance | Elite Vault",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "suspicious_redirect")
        self.assertEqual(analysis["severity"], "high")
        self.assertEqual(analysis["confidence"], 90)
        self.assertIn("rez.onfan.co", analysis["reason"])

    def test_same_domain_redirect_stays_clean(self):
        analysis = main.rule_based_analysis(
            "readerspoll.pitchfork.com",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://www.pitchfork.com/readerspoll",
                "title": "Pitchfork Readers Poll",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")

    def test_conde_nast_okta_redirect_stays_clean(self):
        analysis = main.rule_based_analysis(
            "stag-forktracks.pitchfork.com",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://condenast-hub.oktapreview.com/oauth2/v1/authorize?client_id=test",
                "title": "Sign In",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")

    def test_live_shopify_brand_impersonation_is_critical(self):
        analysis = main.rule_based_analysis(
            "box.vogue.it",
            {
                "nxdomain": False,
                "cname_target": "voguebeautybox.myshopify.com",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://box.vogue.it",
                "title": "MAHKOTA88 Vogue Italia: Kotak Koleksi & Langganan Eksklusif",
                "body_snippet": "MAHKOTA88 adalah portal koleksi & langganan eksklusif Vogue Italia. Price $88 Marketplace MAHKOTA88",
            },
        )

        self.assertEqual(analysis["verdict"], "takeover_vulnerable")
        self.assertEqual(analysis["severity"], "critical")
        self.assertEqual(analysis["provider"], "Shopify")

    def test_conde_nast_emea_okta_redirect_stays_clean(self):
        analysis = main.rule_based_analysis(
            "forktracks.pitchfork.com",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://condenast-hub.okta-emea.com/oauth2/v1/authorize?client_id=test",
                "title": "Condé Nast - Sign In",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")

    def test_conde_io_redirect_stays_clean(self):
        analysis = main.rule_based_analysis(
            "shop.vogue.it",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://conde.io/redirect?next=https://shop.vogue.it",
                "title": "Conde.io",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")

    def test_trusted_redirect_service_stays_clean_across_brand_domains(self):
        analysis = main.rule_based_analysis(
            "offers.gq.it",
            {
                "nxdomain": False,
                "cname_target": "redirects.conde.io",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://subscriptions.gq.de/",
                "title": "GQ Subscriptions",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")

    def test_external_redirect_without_threat_signal_requires_review(self):
        analysis = main.rule_based_analysis(
            "docs.example.com",
            {
                "nxdomain": False,
                "cname_target": "redirect.vendor.example",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://documentation.vendor.example/",
                "title": "Product Documentation",
                "body_snippet": "Documentation portal",
            },
        )

        self.assertEqual(analysis["verdict"], "ownership_validation_required")
        self.assertEqual(analysis["severity"], "medium")
        self.assertEqual(analysis["confidence"], 50)

    def test_s3_global_to_regional_redirect_with_403_is_configuration_issue(self):
        analysis = main.rule_based_analysis(
            "video.pitchforkmedia.com",
            {
                "nxdomain": False,
                "cname_target": "s3.amazonaws.com",
                "cname_target_nxdomain": False,
            },
            {
                "status": 403,
                "url": "https://video.pitchforkmedia.com.s3-ap-southeast-1.amazonaws.com/",
                "title": "",
                "body_snippet": "<Code>AccessDenied</Code>",
            },
        )

        self.assertEqual(analysis["verdict"], "configuration_issue")
        self.assertEqual(analysis["severity"], "info")
        self.assertEqual(analysis["provider"], "AWS S3")
        self.assertIn("configuration issue", analysis["reason"].lower())
        self.assertIn("HTTP 403", analysis["reason"])
        self.assertIn("no missing-bucket takeover fingerprint", analysis["reason"])
        self.assertEqual(analysis["fingerprint_evidence"]["status"], "not_detected")
        self.assertIn("<code>nosuchbucket</code>", analysis["fingerprint_evidence"]["checked"])

    def test_s3_internal_redirect_with_tls_error_explains_certificate_issue(self):
        analysis = main.rule_based_analysis(
            "video.pitchforkmedia.com",
            {
                "nxdomain": False,
                "cname_target": "s3.amazonaws.com",
                "cname_target_nxdomain": False,
            },
            {
                "status": 403,
                "url": "https://video.pitchforkmedia.com.s3-ap-southeast-1.amazonaws.com/",
                "title": "",
                "body_snippet": "<Code>AccessDenied</Code>",
                "tls_error": "certificate verify failed: hostname mismatch",
            },
        )

        self.assertEqual(analysis["verdict"], "configuration_issue")
        self.assertEqual(analysis["severity"], "info")
        self.assertIn("certificate validation failed", analysis["reason"])

    def test_s3_missing_bucket_fingerprint_is_reported(self):
        analysis = main.rule_based_analysis(
            "missing.example.com",
            {
                "nxdomain": False,
                "cname_target": "s3.amazonaws.com",
                "cname_target_nxdomain": False,
            },
            {
                "status": 404,
                "url": "http://missing.example.com/",
                "title": "",
                "body_snippet": "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
            },
        )

        self.assertEqual(analysis["verdict"], "takeover_vulnerable")
        self.assertEqual(analysis["severity"], "critical")
        self.assertEqual(analysis["fingerprint_evidence"]["status"], "matched")
        self.assertEqual(analysis["fingerprint_evidence"]["matched"], "the specified bucket does not exist")

    def test_s3_cname_redirect_to_unrelated_host_still_requires_review(self):
        analysis = main.rule_based_analysis(
            "files.example.com",
            {
                "nxdomain": False,
                "cname_target": "s3.amazonaws.com",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://unrelated.example.net/",
                "title": "Files",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "ownership_validation_required")
        self.assertEqual(analysis["severity"], "medium")

    @patch.dict("os.environ", {"REDIRECT_DOMAIN_ALLOWLIST": "trusted-vendor.example"})
    def test_allowlisted_external_redirect_stays_clean(self):
        analysis = main.rule_based_analysis(
            "login.example.com",
            {
                "nxdomain": False,
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://auth.trusted-vendor.example/login",
                "title": "Sign in",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "clean")


if __name__ == "__main__":
    unittest.main()
