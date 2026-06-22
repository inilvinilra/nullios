import unittest
from pathlib import Path
from unittest.mock import MagicMock

from nullios.analyzer import (
    AnalysisResult,
    _collect_entitlements,
    _collect_universal_links,
    _collect_url_schemes,
)


def _make_bundle(info_plist: dict, provision_entitlements: dict | None = None):
    bundle = MagicMock()
    bundle.info_plist = info_plist
    bundle.embedded_provision = None
    bundle.main_binary_path = None
    if provision_entitlements is not None:
        provision = MagicMock()
        import plistlib
        provision_data = plistlib.dumps({"Entitlements": provision_entitlements})
        provision.read_bytes.return_value = b"garbage" + provision_data + b"trailing"
        bundle.embedded_provision = provision
    return bundle


class URLSchemeTests(unittest.TestCase):
    def test_collect_url_schemes(self):
        bundle = _make_bundle({
            "CFBundleURLTypes": [
                {"CFBundleURLSchemes": ["myapp", "myapp2"]},
                {"CFBundleURLSchemes": ["myapp"]},
            ],
        })
        result = AnalysisResult()
        _collect_url_schemes(bundle, result)
        self.assertEqual(result.url_schemes, ["myapp", "myapp2"])


class UniversalLinkTests(unittest.TestCase):
    def test_associated_domains_from_entitlements(self):
        bundle = _make_bundle(
            {},
            provision_entitlements={
                "com.apple.developer.associated-domains": [
                    "applinks:example.com",
                    "applinks:app.example.com",
                ],
            },
        )
        result = AnalysisResult()
        _collect_entitlements(bundle, result)
        _collect_universal_links(result)
        self.assertEqual(result.universal_links, [
            "applinks:app.example.com",
            "applinks:example.com",
        ])

    def test_ns_user_activity_types_not_treated_as_domains(self):
        bundle = _make_bundle({
            "NSUserActivityTypes": ["com.example.app.view"],
        })
        result = AnalysisResult()
        _collect_entitlements(bundle, result)
        _collect_universal_links(result)
        self.assertEqual(result.universal_links, [])


if __name__ == "__main__":
    unittest.main()
