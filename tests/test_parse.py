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
        lists = {l: "example.com" for l in ["iana", "icann", "mozilla", "custom"]}

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
            "custom": "example.co.uk",
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
            "custom": "putz.priv.at",
        }

        for l, val in lists.items():
            with self.subTest(l=l):
                tld_list = ut_parse_lib.get_public_suffix_list(l)
                parse_result = ut_parse_lib.parse_extended(domain, tld_list)
                self.assertEqual(parse_result["ut_domain"], val)


if __name__ == "__main__":
    unittest.main()
