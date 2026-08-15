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
