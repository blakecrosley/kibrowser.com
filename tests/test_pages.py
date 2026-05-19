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

    def test_well_known_apple_app_site_association(self):
        self.assertAppleAppSiteAssociation("/.well-known/apple-app-site-association")

    def test_root_apple_app_site_association(self):
        self.assertAppleAppSiteAssociation("/apple-app-site-association")


if __name__ == "__main__":
    unittest.main()
