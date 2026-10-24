# hackertarget

Looks a domain or an IP address up in HackerTarget's free API. For a domain it lists the subdomains HackerTarget's host search knows, with the addresses they had, and the domain's DNS records (A, AAAA, MX, NS, TXT, SOA). For an IP address it gives the reverse DNS name, the network (ASN) that announces it and its owner, and the domains hosted on it. Only HackerTarget's passive lookups are used, never its port scans or other tools that send traffic to the target: nothing reaches the target but ordinary DNS queries from HackerTarget's servers.

```
ot run osintverse-community/hackertarget --domain example.com
ot run osintverse-community/hackertarget --ip 8.8.8.8
```

## Inputs

Give exactly one.

| Input | Required | |
| --- | --- | --- |
| `domain` | one of these | Subdomains and DNS records of this domain |
| `ip` | one of these | Reverse DNS, network and hosted domains of this address |

## Keys

None needed. Without a key HackerTarget allows 50 API calls a day from one address, and only about 20 for the host search, reverse IP and reverse DNS lookups; each run makes two calls for a domain or three for an IP address. `HACKERTARGET_API_KEY` (`ot keys set HACKERTARGET_API_KEY`), from a paid membership, lifts the limit: https://hackertarget.com/pricing/. When the day's calls are used up the tool exits with code 1 and says so.

## Notes

Free lookups return at most 500 lines, so a large domain's subdomain list or a busy address's hosted domains are cut short. The subdomains come from HackerTarget's own DNS data, which may include names that no longer resolve. Domains hosted on an address are reported with low confidence when there are more than 20 of them, since that usually means shared hosting or a CDN. A domain HackerTarget doesn't know makes it answer "error invalid host", which exits with code 1.

## Next steps

Find more subdomains in Certificate Transparency logs with [osintverse-community/crtsh-subdomains](https://otinstaller.com/osintverse-community/crtsh-subdomains), or see what runs on an address with [osintverse-community/shodan-internetdb](https://otinstaller.com/osintverse-community/shodan-internetdb).

## Development

```
python -m unittest
ot validate
```

Releases are built, signed and published by the `otinstaller release` workflow (Actions tab, with the version to release).

## License

MIT
