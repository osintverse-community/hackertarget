#!/usr/bin/env python3
"""Looks a domain or an IP address up in HackerTarget's API. For a domain: its subdomains and their addresses, from
HackerTarget's host search, and its DNS records. For an IP address: its reverse DNS name, the network (ASN) that
announces it, and the domains hosted on it.

Only HackerTarget's passive lookups are used, never its port scans or other tools that send traffic to the target.
Works without a key, within a daily allowance of about 20 to 50 calls depending on the lookup; HACKERTARGET_API_KEY,
from a paid membership, lifts it. Prints {"entities": [...]}.
"""
import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEY = "HACKERTARGET_API_KEY"
SOURCE = "hackertarget"
API = "https://api.hackertarget.com/"
USER_AGENT = "osintverse-hackertarget/0.1 (+https://otinstaller.com)"
LOOKUPS = {"domain": ["hostsearch", "dnslookup"], "ip": ["reversedns", "aslookup", "reverseiplookup"]}
SHARED = 20  # more domains than this on one address means shared hosting or a CDN


class APIError(Exception):
    """An error HackerTarget answers in plain text, such as a used-up daily allowance."""


def fetch(lookup, query, key=None):
    """One lookup's plain-text answer; empty when HackerTarget found nothing."""
    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["X-API-Key"] = key
    url = f"{API}{lookup}/?" + urllib.parse.urlencode({"q": query})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:
            text = resp.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as exc:
        if exc.code != 429:
            raise
        try:
            reason = exc.read().decode("utf-8", "replace").strip().partition("\n")[0]
        except (OSError, AttributeError):
            reason = ""
        raise APIError(reason or "too many requests (2 a second at most)") from exc
    first = text.partition("\n")[0].strip()
    if first.lower().startswith(("error", "api count exceeded")):
        raise APIError(first)
    if re.match(r"(?i)no .*\bfound\b", first):
        return ""
    return text


def run_lookups(kind, value, key=None):
    """Every lookup for the kind of target, a moment apart to stay under the API's 2 requests a second."""
    answers = {}
    for i, lookup in enumerate(LOOKUPS[kind]):
        if i:
            time.sleep(0.6)
        answers[lookup] = fetch(lookup, value, key)
    return answers


def hostsearch(text):
    """Each host name with the addresses it had, from "host,address" lines."""
    hosts = {}
    for line in text.splitlines():
        name, _, ip = line.strip().partition(",")
        name, ip = name.strip().rstrip(".").lower(), ip.strip()
        if name:
            ips = hosts.setdefault(name, [])
            if ip and ip not in ips:
                ips.append(ip)
    return hosts


def dnslookup(text):
    """(type, value) pairs, from "TYPE : value" lines."""
    records = []
    for line in text.splitlines():
        rtype, sep, value = line.partition(" : ")
        if sep and rtype.strip() and value.strip():
            records.append((rtype.strip().upper(), value.strip()))
    return records


def aslookup(text):
    """The '"address","asn","network","name, CC"' line; None when no network announces the address."""
    for row in csv.reader(text.splitlines()):
        if len(row) >= 4 and row[1].strip() not in ("", "None"):
            name, country = row[3].strip(), None
            if re.search(r", [A-Z]{2}$", name):
                name, country = name[:-4], name[-2:]
            return {"asn": "AS" + row[1].strip(), "network": row[2].strip() or None, "as_name": name or None,
                    "country": country}
    return None


def names(text, column=0):
    """Host names, one per line (in the given space-separated column), without duplicates."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) > column:
            name = parts[column].rstrip(".").lower()
            if name not in out:
                out.append(name)
    return out


def domain_entities(domain, answers):
    """Subdomains from the host search, then the DNS records, with the addresses and hosts they point to."""
    out, ips = [], {}
    for name, addresses in sorted(hostsearch(answers.get("hostsearch", "")).items()):
        if name == domain or name.endswith("." + domain):
            out.append({"type": "subdomain", "value": name, "source": SOURCE, "confidence": "medium",
                        "attrs": {"domain": domain, "ips": addresses}})
            for ip in addresses:
                ips.setdefault(ip, []).append(name)
    targets = {}
    for rtype, value in dnslookup(answers.get("dnslookup", "")):
        attrs = {"domain": domain, "record_type": rtype}
        if rtype in ("A", "AAAA"):
            attrs["ip"] = value
            ips.setdefault(value, []).append(domain)
        elif rtype in ("NS", "MX", "CNAME") and value.split()[-1] != ".":
            targets.setdefault(value.split()[-1].rstrip(".").lower(), rtype.lower())
        out.append({"type": "dns_record", "value": f"{rtype} {value}", "source": SOURCE, "confidence": "high",
                    "attrs": attrs})
    for ip, hosts in ips.items():
        out.append({"type": "ip", "value": ip, "source": SOURCE, "confidence": "medium",
                    "attrs": {"hosts": sorted(set(hosts))[:20]}})
    for name, relation in targets.items():
        out.append({"type": "domain", "value": name, "source": SOURCE, "confidence": "high",
                    "attrs": {"relation": relation, "domain": domain}})
    return out


def ip_entities(ip, answers):
    """The address with its reverse DNS and network, the network's owner, and the domains hosted on it."""
    ptr = names(answers.get("reversedns", ""), column=1)
    asn = aslookup(answers.get("aslookup", "")) or {}
    hosted = names(answers.get("reverseiplookup", ""))
    if not (ptr or asn or hosted):
        return []
    attrs = {"reverse_dns": ptr, "asn": asn.get("asn"), "network": asn.get("network"), "as_name": asn.get("as_name"),
             "country": asn.get("country"), "hosted_domains": len(hosted)}
    out = [{"type": "ip", "value": ip, "source": SOURCE, "confidence": "high", "attrs": attrs}]
    out += [{"type": "domain", "value": name, "source": SOURCE, "confidence": "high",
             "attrs": {"relation": "reverse DNS of the address", "ip": ip}} for name in ptr]
    if asn.get("as_name"):
        out.append({"type": "organization", "value": asn["as_name"], "source": SOURCE, "confidence": "medium",
                    "attrs": {"role": "network owner", "asn": asn["asn"], "network": asn.get("network"),
                              "country": asn.get("country")}})
    confidence = "low" if len(hosted) > SHARED else "medium"
    out += [{"type": "domain", "value": name, "source": SOURCE, "confidence": confidence,
             "attrs": {"relation": "hosted on the address", "ip": ip}} for name in hosted]
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hackertarget", description="Look a domain or IP address up in HackerTarget.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--domain", help="subdomains and DNS records of this domain")
    target.add_argument("--ip", help="reverse DNS, network and hosted domains of this address")
    args = parser.parse_args(argv)
    kind = "domain" if args.domain else "ip"
    value = getattr(args, kind).strip().rstrip(".").lower()
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            print(f"{value!r} is not an IP address", file=sys.stderr)
            return 2
        if not address.is_global:
            print(f"{address} is a private or reserved address", file=sys.stderr)
            json.dump({"entities": []}, sys.stdout)
            print()
            return 0
        value = str(address)
    key = os.environ.get(KEY, "").strip() or None
    try:
        answers = run_lookups(kind, value, key)
    except APIError as exc:
        hint = "" if key else f"; the free daily allowance is used up, and a membership key in {KEY} lifts it"
        print(f"HackerTarget: {exc}" + (hint if "count exceeded" in str(exc).lower() else ""), file=sys.stderr)
        return 1
    except urllib.error.HTTPError as exc:
        print(f"HackerTarget: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"HackerTarget: {exc}", file=sys.stderr)
        return 1
    found = domain_entities(value, answers) if kind == "domain" else ip_entities(value, answers)
    if not found:
        print(f"HackerTarget found nothing for {value}", file=sys.stderr)
    json.dump({"entities": found}, sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
