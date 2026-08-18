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

    def test_unapproved_readerspoll_redirect_is_critical(self):
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
        self.assertEqual(analysis["severity"], "critical")
        self.assertEqual(analysis["confidence"], 90)
        self.assertIn("rez.onfan.co", analysis["reason"])

    def test_unknown_external_redirect_is_critical(self):
        analysis = main.rule_based_analysis(
            "legacy.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": 200,
                "url": "https://unknown-vendor.example.net/landing",
                "title": "Unknown landing page",
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "suspicious_redirect")
        self.assertEqual(analysis["severity"], "critical")
        self.assertEqual(analysis["confidence"], 90)

    def test_shopify_failure_on_direct_a_record_is_high(self):
        analysis = main.rule_based_analysis(
            "merch.pitchfork.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "a_records": ["23.227.38.32"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 402,
                "url": "https://merch.pitchfork.com",
                "title": "Store unavailable",
                "body_snippet": "",
                "headers": {"powered-by": "Shopify"},
            },
        )

        self.assertEqual(analysis["verdict"], "provider_resource_risk")
        self.assertEqual(analysis["severity"], "high")
        self.assertEqual(analysis["provider"], "Shopify")
        self.assertEqual(analysis["confidence"], 85)
        self.assertIn("HTTP header", analysis["provider_evidence"])

    def test_healthy_shopify_direct_a_record_stays_clean(self):
        analysis = main.rule_based_analysis(
            "shop.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 200,
                "url": "https://shop.example.com",
                "title": "Example Store",
                "body_snippet": "Welcome to our store",
                "headers": {"powered-by": "Shopify"},
            },
        )

        self.assertEqual(analysis["verdict"], "clean")
        self.assertEqual(analysis["severity"], "info")
        self.assertEqual(analysis["provider"], "Shopify")

    def test_heroku_failure_on_direct_a_record_is_high(self):
        analysis = main.rule_based_analysis(
            "app.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 404,
                "url": "https://app.example.com",
                "title": "No such app",
                "body_snippet": "No such app",
                "headers": {"via": "1.1 vegur"},
            },
        )

        self.assertEqual(analysis["verdict"], "provider_resource_risk")
        self.assertEqual(analysis["severity"], "high")
        self.assertEqual(analysis["provider"], "Heroku")

    def test_generic_http_failure_is_info_not_medium(self):
        analysis = main.rule_based_analysis(
            "broken.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 404,
                "url": "https://broken.example.com",
                "title": "Not Found",
                "body_snippet": "Not Found",
                "headers": {},
            },
        )

        self.assertEqual(analysis["verdict"], "http_observation")
        self.assertEqual(analysis["severity"], "info")

    def test_identified_provider_generic_failure_is_medium(self):
        analysis = main.rule_based_analysis(
            "maintenance.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["A"],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 500,
                "url": "https://maintenance.example.com",
                "title": "Maintenance",
                "body_snippet": "Please try again later",
                "headers": {"powered-by": "Shopify"},
            },
        )

        self.assertEqual(analysis["verdict"], "provider_service_error")
        self.assertEqual(analysis["severity"], "medium")
        self.assertEqual(analysis["provider"], "Shopify")

    def test_cloudfront_generic_503_is_medium_service_error(self):
        analysis = main.rule_based_analysis(
            "media.pitchfork.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["CNAME", "A"],
                "query_errors": {},
                "cname_target": "d2zm5qiurbqbji.cloudfront.net",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 503,
                "url": "https://media.pitchfork.com",
                "title": "ERROR: The request could not be satisfied",
                "body_snippet": "The request could not be satisfied.",
                "headers": {},
            },
        )

        self.assertEqual(analysis["verdict"], "provider_service_error")
        self.assertEqual(analysis["severity"], "medium")
        self.assertEqual(analysis["provider"], "AWS CloudFront")

    def test_permutive_branded_default_page_is_info(self):
        analysis = main.rule_based_analysis(
            "permutive.pitchfork.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["CNAME", "A"],
                "query_errors": {},
                "cname_target": "tbipw9d1vxkk.customer.permutive.app",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 404,
                "url": "https://permutive.pitchfork.com",
                "title": "Nope!",
                "body_snippet": (
                    "It is not here. Whatever you are looking for, this is not it! "
                    "Don't need to try again. Permutive."
                ),
                "headers": {},
            },
        )

        self.assertEqual(analysis["verdict"], "vendor_default_page")
        self.assertEqual(analysis["severity"], "info")
        self.assertEqual(analysis["provider"], "Permutive")
        self.assertEqual(analysis["confidence"], 80)

    def test_s3_missing_bucket_signature_is_high_not_critical(self):
        analysis = main.rule_based_analysis(
            "assets.example.com",
            {
                "nxdomain": False,
                "resolves": True,
                "record_types": ["CNAME", "A"],
                "query_errors": {},
                "cname_target": "missing-bucket.s3.amazonaws.com",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": True,
                "status": 404,
                "url": "https://assets.example.com",
                "title": "NoSuchBucket",
                "body_snippet": "<Code>NoSuchBucket</Code> The specified bucket does not exist",
                "headers": {"server": "AmazonS3"},
            },
        )

        self.assertEqual(analysis["verdict"], "takeover_vulnerable")
        self.assertEqual(analysis["severity"], "high")

    def test_dns_query_failure_is_scan_error_not_clean(self):
        analysis = main.rule_based_analysis(
            "unclassified.example.com",
            {
                "nxdomain": False,
                "resolves": False,
                "record_types": [],
                "query_errors": {"A": "SERVFAIL / no nameservers available"},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "attempted": False,
                "status": None,
                "url": None,
                "title": None,
                "body_snippet": "",
                "headers": {},
            },
        )

        self.assertEqual(analysis["verdict"], "scan_error")
        self.assertEqual(analysis["severity"], "info")

    def test_nodata_without_web_records_is_not_resolving(self):
        analysis = main.rule_based_analysis(
            "empty.example.com",
            {
                "nxdomain": False,
                "resolves": False,
                "record_types": [],
                "query_errors": {},
                "cname_target": "",
                "cname_target_nxdomain": False,
            },
            {
                "status": None,
                "url": None,
                "title": None,
                "body_snippet": "",
            },
        )

        self.assertEqual(analysis["verdict"], "inactive")
        self.assertEqual(analysis["severity"], "info")
        self.assertIn("no A, AAAA, or CNAME", analysis["reason"])

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
