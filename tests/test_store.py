import unittest
from unittest.mock import patch

from nullios.store import StoreCredentials, resolve_target


class ResolveTargetTests(unittest.TestCase):
    def test_bundle_id_passes_through(self):
        self.assertEqual(resolve_target("com.example.app"), "com.example.app")

    def test_store_id_lookup(self):
        with patch("nullios.store.requests.get") as mock_get:
            mock_get.return_value.json.return_value = {
                "results": [{"bundleId": "com.example.app"}],
            }
            self.assertEqual(resolve_target("123456789"), "com.example.app")
            mock_get.assert_called_once()

    def test_app_store_url_lookup(self):
        with patch("nullios.store.requests.get") as mock_get:
            mock_get.return_value.json.return_value = {
                "results": [{"bundleId": "com.example.app"}],
            }
            self.assertEqual(
                resolve_target("https://apps.apple.com/us/app/example/id123456789"),
                "com.example.app",
            )


class StoreCredentialsTests(unittest.TestCase):
    def test_from_env(self):
        with patch.dict("os.environ", {
            "NULLIOS_APPLE_ID": "test@example.com",
            "NULLIOS_APPLE_PASSWORD": "secret",
        }):
            creds = StoreCredentials.from_env()
            self.assertIsNotNone(creds)
            self.assertEqual(creds.apple_id, "test@example.com")
            self.assertEqual(creds.password, "secret")


if __name__ == "__main__":
    unittest.main()
