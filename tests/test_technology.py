"""
Tests for TechnologyService passive detection signatures.
"""

import unittest
from services.technology_service import TechnologyService

class TestTechnologyService(unittest.TestCase):
    def test_detect_web_server(self):
        headers = {"server": "nginx/1.24.0"}
        techs = TechnologyService.detect(headers)
        names = [t["name"] for t in techs]
        self.assertTrue(any("Nginx" in n for n in names))

    def test_detect_cms_wordpress(self):
        html = '<html><head><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/style.css"></head></html>'
        techs = TechnologyService.detect({}, body_html=html)
        names = [t["name"] for t in techs]
        self.assertIn("WordPress", names)

    def test_detect_framework_django_cookie(self):
        cookies = [{"name": "csrftoken", "value": "xyz123"}]
        techs = TechnologyService.detect({}, cookies=cookies)
        names = [t["name"] for t in techs]
        self.assertIn("Django", names)

    def test_detect_cdn_cloudflare(self):
        headers = {"cf-ray": "82a1b2c3d4e5f6-IAD", "server": "cloudflare"}
        techs = TechnologyService.detect(headers)
        names = [t["name"] for t in techs]
        self.assertIn("Cloudflare", names)

if __name__ == "__main__":
    unittest.main()
