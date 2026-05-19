import json
import unittest

from fastapi.testclient import TestClient

from app.main import app


class AppleAppSiteAssociationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def assertAppleAppSiteAssociation(self, path):
        response = self.client.get(path)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["cache-control"], "public, max-age=3600")
        self.assertEqual(
            json.loads(response.text),
            {"webcredentials": {"apps": ["M4WTLM6RAQ.com.941apps.Ki"]}},
        )

    def assertAppleAppSiteAssociationHead(self, path):
        response = self.client.head(path)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["cache-control"], "public, max-age=3600")
        self.assertEqual(response.content, b"")

    def test_well_known_apple_app_site_association(self):
        self.assertAppleAppSiteAssociation("/.well-known/apple-app-site-association")

    def test_root_apple_app_site_association(self):
        self.assertAppleAppSiteAssociation("/apple-app-site-association")

    def test_well_known_apple_app_site_association_head(self):
        self.assertAppleAppSiteAssociationHead("/.well-known/apple-app-site-association")

    def test_root_apple_app_site_association_head(self):
        self.assertAppleAppSiteAssociationHead("/apple-app-site-association")


class ApplePasswordsTestPageTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_test_page_has_noindex_login_form(self):
        response = self.client.get("/apple-passwords-test")

        self.assertEqual(response.status_code, 200)
        self.assertIn('<meta name="robots" content="noindex, nofollow">', response.text)
        self.assertIn('id="ki-test-username"', response.text)
        self.assertIn('name="username"', response.text)
        self.assertIn('autocomplete="username"', response.text)
        self.assertIn('id="ki-test-password"', response.text)
        self.assertIn('name="password"', response.text)
        self.assertIn('type="password"', response.text)
        self.assertIn('autocomplete="current-password"', response.text)
        self.assertIn('Use non-sensitive test values only.', response.text)


if __name__ == "__main__":
    unittest.main()
