import io
import json
import os
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import hackertarget

HOSTSEARCH = "www.example.com,93.184.215.14\napi.example.com,93.184.215.20\nAPI.example.com.,93.184.215.21\n" \
             "example.com.evil.net,10.0.0.1\n"
DNSLOOKUP = "A : 93.184.215.14\nAAAA : 2606:2800:21f:cb07:6820:80da:af6b:8b2c\nMX : 0 .\n" \
            "NS : a.iana-servers.net.\nTXT : v=spf1 -all"


def response(text):
    resp = mock.MagicMock()
    resp.__enter__.return_value.read.return_value = text.encode()
    return resp


def run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}, clear=True), redirect_stdout(out), redirect_stderr(err):
        code = hackertarget.main(argv)
    return code, out.getvalue(), err.getvalue()


class HackerTargetTest(unittest.TestCase):
    def test_domain_entities(self):
        found = hackertarget.domain_entities("example.com", {"hostsearch": HOSTSEARCH, "dnslookup": DNSLOOKUP})
        subdomains = {e["value"]: e["attrs"]["ips"] for e in found if e["type"] == "subdomain"}
        self.assertEqual(subdomains, {"api.example.com": ["93.184.215.20", "93.184.215.21"],
                                      "www.example.com": ["93.184.215.14"]})
        records = [e for e in found if e["type"] == "dns_record"]
        self.assertEqual([e["value"] for e in records][:2],
                         ["A 93.184.215.14", "AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
        self.assertEqual(records[0]["attrs"], {"domain": "example.com", "record_type": "A", "ip": "93.184.215.14"})
        ips = {e["value"]: e["attrs"]["hosts"] for e in found if e["type"] == "ip"}
        self.assertEqual(ips["93.184.215.14"], ["example.com", "www.example.com"])
        self.assertNotIn("10.0.0.1", ips)
        self.assertEqual([(e["value"], e["attrs"]["relation"]) for e in found if e["type"] == "domain"],
                         [("a.iana-servers.net", "ns")])

    def test_ip_entities(self):
        answers = {"reversedns": "8.8.8.8 dns.google", "aslookup": '"8.8.8.8","15169","8.8.8.0/24","GOOGLE, US"',
                   "reverseiplookup": "dns.google\nexample.org\n"}
        found = hackertarget.ip_entities("8.8.8.8", answers)
        self.assertEqual([e["type"] for e in found], ["ip", "domain", "organization", "domain", "domain"])
        self.assertEqual(found[0]["attrs"]["asn"], "AS15169")
        self.assertEqual(found[0]["attrs"]["hosted_domains"], 2)
        self.assertEqual(found[2]["value"], "GOOGLE")
        self.assertEqual(found[2]["attrs"]["country"], "US")
        self.assertEqual(found[3]["confidence"], "medium")

    def test_shared_hosting_is_low_confidence(self):
        hosted = "\n".join(f"site{i}.example" for i in range(hackertarget.SHARED + 1))
        found = hackertarget.ip_entities("192.0.2.1", {"reverseiplookup": hosted})
        self.assertEqual({e["confidence"] for e in found if e["type"] == "domain"}, {"low"})

    def test_nothing_known_is_no_entities(self):
        self.assertEqual(hackertarget.ip_entities("10.0.0.1", {"aslookup": '"10.0.0.1","None","None",""'}), [])

    def test_fetch_errors_and_empty_answers(self):
        with mock.patch("urllib.request.urlopen", return_value=response("No DNS A records found for x")):
            self.assertEqual(hackertarget.fetch("reverseiplookup", "192.0.2.1"), "")
        with mock.patch("urllib.request.urlopen", return_value=response("error invalid host")), \
                self.assertRaises(hackertarget.APIError):
            hackertarget.fetch("hostsearch", "nope.invalid")

    def test_429_keeps_the_answer(self):
        error = urllib.error.HTTPError(hackertarget.API, 429, "Too Many Requests", {},
                                       io.BytesIO(b"API count exceeded - Increase Quota with Membership"))
        with mock.patch("urllib.request.urlopen", side_effect=error), \
                self.assertRaisesRegex(hackertarget.APIError, "API count exceeded"):
            hackertarget.fetch("hostsearch", "example.com")

    def test_key_goes_in_a_header(self):
        with mock.patch("urllib.request.urlopen", return_value=response("x")) as urlopen:
            hackertarget.fetch("hostsearch", "example.com", "secret")
        req = urlopen.call_args[0][0]
        self.assertEqual(req.get_header("X-api-key"), "secret")
        self.assertNotIn("secret", req.full_url)

    def test_runs_the_domain_lookups(self):
        calls = []

        def fake_fetch(lookup, query, key=None):
            calls.append((lookup, query, key))
            return {"hostsearch": HOSTSEARCH, "dnslookup": DNSLOOKUP}[lookup]

        with mock.patch.object(hackertarget, "fetch", fake_fetch), mock.patch("time.sleep"):
            code, out, _ = run(["--domain", "Example.COM."])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("hostsearch", "example.com", None), ("dnslookup", "example.com", None)])
        self.assertIn("www.example.com", [e["value"] for e in json.loads(out)["entities"]])

    def test_used_up_allowance_exits_1_with_a_hint(self):
        error = hackertarget.APIError("API count exceeded - Increase Quota with Membership")
        with mock.patch.object(hackertarget, "fetch", side_effect=error), mock.patch("time.sleep"):
            code, out, err = run(["--ip", "8.8.8.8"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("HACKERTARGET_API_KEY", err)

    def test_private_address_is_not_looked_up(self):
        with mock.patch.object(hackertarget, "fetch") as fetch:
            code, out, _ = run(["--ip", "192.168.1.1"])
        fetch.assert_not_called()
        self.assertEqual((code, json.loads(out)), (0, {"entities": []}))

    def test_bad_address_exits_2(self):
        self.assertEqual(run(["--ip", "example.com"])[0], 2)

    def test_needs_exactly_one_target(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
            hackertarget.main(["--domain", "example.com", "--ip", "8.8.8.8"])
        self.assertEqual(stop.exception.code, 2)

    def test_http_error_exits_1(self):
        error = urllib.error.HTTPError(hackertarget.API, 503, "Service Unavailable", {}, io.BytesIO())
        with mock.patch("urllib.request.urlopen", side_effect=error):
            code, _, err = run(["--domain", "example.com"])
        self.assertEqual(code, 1)
        self.assertIn("503", err)


if __name__ == "__main__":
    unittest.main()
