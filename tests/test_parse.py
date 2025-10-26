import os
import sys
import unittest
from pathlib import Path

SPLUNK_HOME = os.environ.get("SPLUNK_HOME")

if SPLUNK_HOME:
    log_path = Path(os.environ["SPLUNK_HOME"]) / "var" / "log " / "splunk"
    log_path.mkdir(parents=True, exist_ok=True)
    (log_path / Path("utbox.log")).write_text("")


bin_path = Path(__file__).resolve().parents[1] / "utbox" / "bin"

sys.path.append(str(bin_path))


import ut_parse_lib


class TestParseMethods(unittest.TestCase):

    def test_parse_iana_domain(self):
        domain = "http://www.example.com/123/123.php"
        lists = {l: "example.com" for l in ["iana", "icann", "mozilla"]}

        for l in lists:
            with self.subTest(l=l):
                tld_list = ut_parse_lib.get_public_suffix_list(l)
                parse_result = ut_parse_lib.parse_extended(domain, tld_list)
                self.assertEqual(parse_result["ut_domain"], "example.com")

    def test_parse_psl_domain(self):
        domain = "http://www.example.co.uk/123/123.php"
        lists = {
            "iana": "co.uk",
            "icann": "example.co.uk",
            "mozilla": "example.co.uk",
        }

        for l, val in lists.items():
            with self.subTest(l=l):
                tld_list = ut_parse_lib.get_public_suffix_list(l)
                parse_result = ut_parse_lib.parse_extended(domain, tld_list)
                self.assertEqual(parse_result["ut_domain"], val)

    def test_parse_private_domain(self):
        domain = "http://putz.priv.at/123/123.php"
        lists = {
            "iana": "priv.at",
            "icann": "priv.at",
            "mozilla": "putz.priv.at",
        }

        for l, val in lists.items():
            with self.subTest(l=l):
                tld_list = ut_parse_lib.get_public_suffix_list(l)
                parse_result = ut_parse_lib.parse_extended(domain, tld_list)
                self.assertEqual(parse_result["ut_domain"], val)

    def test_mozilla_domains(self):
        # Parsing data/tests.txt from https://github.com/publicsuffix/list/tree/main/tests
        tests = Path("data") / "publicsuffix_tests.txt"
        tld_list = ut_parse_lib.get_public_suffix_list("mozilla")
        for line in tests.read_text().splitlines():
            if not line or line.startswith("//"):
                continue
            domain, expected = line.split(" ", 1)
            domain = "None" if domain == "null" else domain
            expected = "None" if expected == "null" else expected
            with self.subTest(domain=domain):
                parse_result = ut_parse_lib.parse_extended(domain, tld_list)
                self.assertEqual(parse_result["ut_domain"], expected)

    def test_parse_protocol(self):
        urls = {
            "http://www.example.com/123/123.php": "80",
            "https://www.example.com/123/123.php": "443",
            "https://www.example.com:8443/123/123.php": "8443",
            "ftp://www.example.com/123/123.php": "21",
        }

        tld_list = ut_parse_lib.get_public_suffix_list("mozilla")
        for url, port in urls.items():
            with self.subTest(url=url):
                parse_result = ut_parse_lib.parse_extended(url, tld_list)
                self.assertEqual(parse_result["ut_port"], port)

    def test_ip_host(self):
        urls = {
            "https://192.0.46.8/123/123.php": "192.0.46.8",
            "https://192.0.46.8:8443/123/123.php": "192.0.46.8",
            "https://[2620:0000:2830:0200:0000:0000:000b:0008]/123abc/123abc.php": "2620:0:2830:200::b:8",
            "https://[2620:0000:2830:0200:0000:0000:000b:0008]:8443/123abc/123abc.php": "2620:0:2830:200::b:8",
        }

        tld_list = ut_parse_lib.get_public_suffix_list("mozilla")
        for url, ip in urls.items():
            with self.subTest(url=url):
                parse_result = ut_parse_lib.parse_extended(url, tld_list)
                self.assertEqual(parse_result["ut_tld"], "None")
                self.assertEqual(parse_result["ut_domain_without_tld"], ip)


if __name__ == "__main__":
    unittest.main()
