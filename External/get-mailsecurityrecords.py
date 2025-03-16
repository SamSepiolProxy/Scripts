#!/usr/bin/env python3
"""
get-mailsecurityrecords.py – Command‐line tool that performs DNS/email authentication checks.

"""

import sys
import requests
import re
import html
import uuid
from urllib.parse import urlparse

# ANSI color codes for terminal output
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

# Global badge counter (to tally warnings)
badge = 0
def update_badge(delta=1):
    global badge
    badge += delta

# Define common double TLDs (needed by get_root_domain)
commonTLDs = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'edu.au', 'com.au', 'net.au', 'co.jp', 'co.com', 'us.org', 'com.kp', 'com.ee']

# -------------------------------------------------------------------
# Full list of DKIM selectors as provided in the JS code
DKIMSelectors = [
    "1024", "fid48", "2020-07", "04042017", "0xdeadbeef", "1", "1000073432", "10dkim1", "11dkim1", "123", "12345",
    "12dkim1", "13q2", "2", "2005", "200505", "2006", "200608", "2007", "2008", "2009", "2010", "2011", "2012",
    "2013", "2014", "2015", "20150120150420144305.pm", "2016", "20160523212918pm", "2017", "2018", "2019",
    "2020", "2021", "2022", "2023", "2024", "247", "3", "384", "512", "768", "86", "ac_v1", "ac_v2", "allselector",
    "alpha", "amazonses", "amazonses2", "amazonses3", "amp", "api", "auth", "authsmtp", "aweber_key_a", "aweber_key_b",
    "aweber_key_c", "bdk", "benchmarkemail", "beta", "bfi", "b-rail", "brj", "bronto", "bronto2", "bronto3", "C2",
    "ca", "care", "ccnt", "ccnt2", "ccnt3", "centralsmtp", "cerner-2", "ciprod", "class", "cm", "cmail1", "cmail2",
    "cmail3", "cmail4", "coa", "connect_1", "convio1", "corp", "Corporate", "critsend2", "cv-usprod-1", "d2005",
    "d2006", "d2007", "d2008", "d2009", "d2010", "d2011", "d2012", "d2013", "d2014", "d2015", "d2016", "d2017",
    "d2018", "d2019", "d2020", "d2021", "d2022", "d2023", "d2024", "default", "default1k", "delta", "desmoines", "dk",
    "dk01", "dk02", "dk03", "dk04", "dk05", "dk06", "dk07", "dk08", "dk09", "dk1", "dk10", "dk1024", "dk1024-2012",
    "dk1024-2013", "dk1024-2014", "dk1024-2015", "dk1024-2016", "dk1024-2017", "dk1024-2018", "dk1024-2019",
    "dk1024-2020", "dk1024-2021", "dk1024-2022", "dk1024-2023", "dk1024-2024", "dk11", "dk12", "dk13", "dk14", "dk15",
    "dk16", "dk17", "dk18", "dk19", "dk2", "dk20", "dk2005", "dk20050327", "dk2006", "dk2007", "dk2008", "dk2009",
    "dk2010", "dk2011", "dk2012", "dk2013", "dk2014", "dk2015", "dk2016", "dk2017", "dk2018", "dk2019", "dk2020",
    "dk2021", "dk2022", "dk2023", "dk2024", "dk2048", "dk256", "dk3", "dk384", "dk4", "dk5", "dk512", "dk6", "dk7",
    "dk768", "dk8", "dk9", "_dkim", "dkim", "dkim01", "dkim02", "dkim03", "dkim04", "dkim05", "dkim06", "dkim07",
    "dkim08", "dkim09", "dkim1", "dkim10", "dkim1024", "dkim11", "dkim12", "dkim13", "dkim14", "dkim15", "dkim16",
    "dkim17", "dkim18", "dkim19", "dkim1k", "dkim2", "dkim20", "dkim-201303", "dkim2048", "dkim256", "dkim3",
    "dkim384", "dkim4", "dkim5", "dkim512", "dkim6", "dkim7", "dkim768", "dkim8", "dkim9", "dkimmail", "dkimrnt",
    "dkim_s1024", "dkrnt", "dksel", "domk", "duh", "dyn", "dyn2", "dyn3", "dynect", "dynect1213", "eb1", "eb10",
    "eb11", "eb12", "eb13", "eb14", "eb15", "eb16", "eb17", "eb18", "eb19", "eb2", "eb20", "eb3", "eb4", "eb5", "eb6",
    "eb7", "eb8", "eb9", "ebmailerd", "ec", "eclinicalmail", "ED-DKIM", "ED-DKIM-V3", "eentf", "ei", "elq", "elq2",
    "elq3", "email0517", "emailvision", "emarsys", "emarsys1", "emarsys2", "emarsys2007", "emarsys3", "emk01", "emma",
    "emv", "ent", "et", "et1", "et2", "et3", "everlytickey1", "everlytickey2", "exacttarget", "exim", "exim4u",
    "expertsender", "EXPNSER28042022", "facebook", "fandango", "fishbowl", "fitnessintl", "fm1", "fm2", "fm3",
    "fm4", "fm5", "fm6", "fm7", "fm8", "fm9", "fnt", "gamma", "gears", "global", "gmmailerd", "godaddy", "goldlasso",
    "google", "googleapps", "hilton", "hs1", "hs2", "hubris", "hubspot1", "hubspot2", "hubspot3", "icontact", "iconzdkim",
    "id", "insideapple0517", "insideapple2048", "insideicloud2048", "iport", "iron.johnscreek7", "itunes", "itunes2048",
    "iweb", "jul13mimi", "k1", "k10", "k11", "k12", "k13", "k14", "k15", "k16", "k17", "k18", "k19", "k2", "k20",
    "k3", "k4", "k5", "k6", "k7", "k8", "k9", "key", "key1", "key10", "key11", "key12", "key13", "key14", "key15",
    "key16", "key17", "key18", "key19", "key2", "key20", "key3", "key4", "key5", "key6", "key7", "key8", "key9", "krs",
    "listrak", "lists", "locaweb", "ls1", "ls10", "ls11", "ls12", "ls13", "ls14", "ls15", "ls16", "ls17", "ls18",
    "ls19", "ls2", "ls20", "ls3", "ls4", "ls5", "ls6", "ls7", "ls8", "ls9", "lufthansa-group", "m", "m1", "m10",
    "m1024", "m11", "m12", "m13", "m14", "m15", "m16", "m17", "m18", "m19", "m2", "m20", "m2048", "m21", "m22",
    "m23", "m24", "m25", "m3", "m384", "m4", "m5", "m512", "m6", "m7", "m768", "m8", "m9", "mail", "mail1", "mail2",
    "mail3", "mail4", "mail5", "mailchannels", "mailchannels1", "mailchannels2", "mailchannels3", "mailchannels4",
    "mailchannels5", "mail-dkim", "mailer", "mailgun", "mailigen", "mail-in", "mailjet", "mailjet1", "mailjet2",
    "mailo", "mailrelay", "main", "mandrill", "marketo", "mcdkim", "mcdkim1", "mcdkim2", "mcdkim3", "mcdkim4",
    "mcdkim5", "mdaemon", "mesmtp", "messagebus", "mg", "mga", "mikd", "mimecast", "mimecast20230622", "mimi",
    "mixmax", "mixpanel", "mkt", "ml", "ml1", "ml2", "ml3", "monkey", "msa", "mt", "mta0", "mx", "mxvault", "my1",
    "my10", "my11", "my12", "my13", "my14", "my15", "my16", "my17", "my18", "my19", "my2", "my20", "my3", "my4",
    "my5", "my6", "my7", "my8", "my9", "yahoo", "yandex", "yesmail", "yesmail1", "yesmail10", "yesmail11", "yesmail12",
    "yesmail13", "yesmail14", "yesmail15", "yesmail16", "yesmail17", "yesmail18", "yesmail19", "yesmail2", "yesmail20",
    "yesmail3", "yesmail4", "yesmail5", "yesmail6", "yesmail7", "yesmail8", "yesmail9", "yibm", "ym1024", "ymail",
    "ymail4", "yousendit", "zendesk1", "zendesk2", "zendesk3", "zendesk4", "zm1", "zoho"
]

# -------------------------------------------------------------------
# Full list of ARC selectors as provided in the JS code
ARCSelectors = [
    "arc", "arc1", "arc-1024", "arc2", "arc-2000", "arc-2001", "arc-2002", "arc-2003", "arc-2004", "arc-2005",
    "arc-2006", "arc-2007", "arc-2008", "arc-2009", "arc-2010", "arc-2011", "arc-2012", "arc-2013", "arc-2014",
    "arc-2015", "arc-2016", "arc-2017", "arc-2018", "arc-2019", "arc-2020", "arc-2021", "arc-2022", "arc-2023",
    "arc-2024", "arc-2025", "arc-2048", "arc3", "arc-384", "arc4", "arc-4096", "arc-512", "arc-768", "arcs",
    "arc-seal", "arcsel", "arcselector", "arcselector1", "arcselector2", "arcselector3", "arcselector4",
    "arcselector5", "arcselector9901", "zohoarc"
]

# -------------------------------------------------------------------
# Utility functions

def fetch_json(url, params=None):
    headers = {'Accept': 'application/dns-json'}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"{RED}Error fetching URL {url}: {e}{RESET}")
        return None

def fetch_domain_info(domain):
    """
    Check if a domain is available (returns True if 404, meaning it can be registered)
    """
    url = f"https://rdap.net/domain/{domain}"
    try:
        response = requests.get(url, timeout=10)
        return response.status_code == 404
    except Exception as e:
        print(f"{RED}Error checking domain {domain}: {e}{RESET}")
        return False

def check_spf_domain_available(dns_record):
    """
    Parse an SPF record string to extract domains from include: and redirect=,
    then check which of those domains are available.
    Returns (available_domains, unique_spf_domains)
    """
    dns_record = dns_record.replace("&#34;", "")
    includes = re.findall(r"include:([^ ]+)", dns_record)
    redirects = re.findall(r"redirect=([^ ]+)", dns_record)
    domains = list(set(includes + redirects))
    domains = [get_root_domain(x) for x in domains if x]
    available = []
    for d in domains:
        if fetch_domain_info(d):
            available.append(d)
    return available, domains

def highlight_substrings(record, red_list, blue_list, green_list):
    """
    Insert ANSI colors into the record for CLI output.
    """
    result = record
    for token in red_list:
        if token:
            result = re.sub(re.escape(token), f"{RED}{token}{RESET}", result)
    for token in blue_list:
        if token:
            result = re.sub(re.escape(token), f"{BLUE}{token}{RESET}", result)
    for token in green_list:
        if token:
            result = re.sub(re.escape(token), f"{GREEN}{token}{RESET}", result)
    return result

def get_root_domain(host):
    """
    Given a hostname (or URL), return the root domain taking into account common TLDs.
    """
    host = host.replace('"', '').replace("'", "")
    parts = host.split('.')
    if len(parts) < 2:
        return host
    candidate = parts[-2] + "." + parts[-1]
    if candidate in commonTLDs and len(parts) >= 3:
        return parts[-3] + "." + candidate
    return candidate

# -------------------------------------------------------------------
# DNS Record Check functions

def check_record(api_url, domain, header):
    """
    Query a DNS record using Cloudflare's DNS-over-HTTPS API and print checks.
    """
    print(f"\n=== {header} check for {domain} ===")
    data = fetch_json(api_url)
    if not data or "Answer" not in data or len(data["Answer"]) == 0:
        if header == "MX":
            print(f"{RED}No {header} record found. This domain cannot receive emails.{RESET}")
        else:
            print(f"{BLUE}No {header} record found for {domain}.{RESET}")
        return

    for ans in data["Answer"]:
        rec = html.unescape(ans.get("data", ""))
        if header in ["SPF", "_SPF"]:
            if "v=spf1" in rec:
                red_tokens = ["+all", "?all", "v=spf2.0", "v=spf2", "ptr"]
                blue_tokens = ["redirect=", "include:", "relay.mailchannels.net", "exp=", "-all", "exists:", " ip4:", " ip6:"]
                green_tokens = ["~all"]
                highlighted = highlight_substrings(rec, red_tokens, blue_tokens, green_tokens)
                print(f"SPF Record: {highlighted}")
                if ("?all" in rec) or ("+all" in rec) or (" all" in rec and not any(x in rec for x in ["~all", "-all", "redirect="])):
                    update_badge()
                    print(f"{RED}Warning: SPF record may be insecure.{RESET}")
                avail, spf_domains = check_spf_domain_available(rec)
                if avail:
                    print(f"{RED}SPF domain(s) available to purchase: {', '.join(avail)}{RESET}")
                    update_badge()
                else:
                    print(f"{GREEN}SPF domains in use: {', '.join(spf_domains)}{RESET}")
            else:
                print(f"{RED}Invalid SPF record: {rec}{RESET}")
        elif header in ["DMARC", "CNAME_DMARC"]:
            if "v=DMARC1" in rec:
                red_tokens = ["sp=none", "p=none"]
                blue_tokens = ["aspf=r", "adkim=r", "fo=d", "fo=s", "redirect="]
                green_tokens = ["sp=reject", "p=reject", "rua=", "ruf="]
                highlighted = highlight_substrings(rec, red_tokens, blue_tokens, green_tokens)
                print(f"DMARC Record: {highlighted}")
                if "pct=" in rec and "pct=100" not in rec:
                    update_badge()
                    m = re.search(r"pct=(\d+)", rec)
                    if m:
                        pct = int(m.group(1))
                        print(f"{RED}Warning: DMARC pct is set to {pct} (not 100).{RESET}")
                if ("rua=" in rec and "mailto:" not in rec) or ("ruf=" in rec and "mailto:" not in rec):
                    update_badge()
                    print(f"{RED}Warning: DMARC rua/ruf missing 'mailto:' prefix.{RESET}")
            else:
                print(f"{RED}No valid DMARC record: {rec}{RESET}")
        elif header == "MX":
            parts = rec.split()
            if len(parts) >= 2:
                mx_server = parts[1].rstrip(".")
                print(f"MX Record: {mx_server}")
            else:
                print(f"{RED}Invalid MX record: {rec}{RESET}")
        elif header == "DNSSEC":
            print(f"DNSSEC Record: {rec}")
        else:
            print(f"{header} Record: {rec}")

def fetch_mta_sts(domain):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            return resp.text
    except Exception:
        pass
    return None

def get_dkim_record(selector, domain):
    """
    Query for a DKIM TXT record using a given selector.
    """
    url = "https://cloudflare-dns.com/dns-query"
    params = {"name": f"{selector}._domainkey.{domain}", "type": "TXT"}
    data = fetch_json(url, params)
    if data and "Answer" in data and len(data["Answer"]) > 0:
        return html.unescape(data["Answer"][0].get("data", ""))
    return None

def check_dkim(domain):
    """
    Loop through all DKIMSelectors and print found DKIM records.
    """
    print(f"\n=== DKIM check for {domain} ===")
    found = False
    for selector in DKIMSelectors:
        record = get_dkim_record(selector, domain)
        if record:
            found = True
            clean_rec = record.replace('&#34;', '').replace('"', '').replace(" ", "")
            print(f"DKIM ({selector}): {clean_rec}")
            if "h=sha1" in clean_rec:
                update_badge()
                print(f"{RED}Warning: DKIM selector {selector} uses SHA-1.{RESET}")
    if not found:
        update_badge()
        print(f"{RED}No DKIM records found for {domain}.{RESET}")

def check_arc(domain):
    """
    Loop through all ARCSelectors and print found ARC records.
    """
    print(f"\n=== ARC check for {domain} ===")
    found = False
    for selector in ARCSelectors:
        url = "https://cloudflare-dns.com/dns-query"
        params = {"name": f"{selector}._domainkey.{domain}", "type": "TXT"}
        data = fetch_json(url, params)
        if data and "Answer" in data and len(data["Answer"]) > 0:
            found = True
            rec = html.unescape(data["Answer"][0].get("data", ""))
            clean_rec = rec.replace('&#34;', '').replace('"', '').replace(" ", "")
            print(f"ARC ({selector}): {clean_rec}")
            if "h=sha1" in clean_rec:
                update_badge()
                print(f"{RED}Warning: ARC selector {selector} uses SHA-1.{RESET}")
    if not found:
        print(f"{BLUE}No ARC records found for {domain}.{RESET}")

def check_dane(domain):
    """
    For each MX record (plus the root domain), query for a TLSA (DANE) record.
    """
    print(f"\n=== DANE check for {domain} ===")
    mx_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"
    data = fetch_json(mx_url)
    mx_servers = []
    if data and "Answer" in data:
        for rec in data["Answer"]:
            parts = rec.get("data", "").split()
            if len(parts) >= 2:
                mx_servers.append(parts[1].rstrip("."))
        mx_servers.append(domain)
    else:
        print(f"{BLUE}No MX records found for DANE check.{RESET}")
        return

    for mx in mx_servers:
        tlsa_name = f"_25._tcp.{mx}"
        params = {"name": tlsa_name, "type": "TLSA"}
        dane_data = fetch_json("https://cloudflare-dns.com/dns-query", params)
        if dane_data and "Answer" in dane_data and len(dane_data["Answer"]) > 0:
            for ans in dane_data["Answer"]:
                print(f"DANE for {mx}: {html.unescape(ans.get('data', ''))}")
        else:
            print(f"No DANE record found for {mx}.")

def query_nsec(domain):
    url = "https://cloudflare-dns.com/dns-query"
    params = {"name": domain, "type": "NSEC"}
    data = fetch_json(url, params)
    if data and "Answer" in data and len(data["Answer"]) > 0:
        nsec_data = data["Answer"][0].get("data", "")
        names = [x for x in nsec_data.split() if x != "."]
        return names
    return []

def check_nsec(domain):
    print(f"\n=== NSEC check for {domain} ===")
    names = query_nsec(domain)
    if names:
        print(f"NSEC records ({len(names)}):")
        for n in sorted(names):
            print(n)
    else:
        print(f"{BLUE}No NSEC records found for {domain}.{RESET}")

def check_nsec3(domain):
    print(f"\n=== NSEC3 check for {domain} ===")
    nsec3_hashes = set()
    for _ in range(50):
        rand_sub = f"{uuid.uuid4()}.{domain}"
        url = "https://cloudflare-dns.com/dns-query"
        params = {"name": rand_sub, "type": "NSEC", "do": "1"}
        data = fetch_json(url, params)
        if data and "Authority" in data:
            for rec in data["Authority"]:
                if rec.get("type") == 50:
                    nsec3_hashes.add(rec.get("name", "").lower())
    if nsec3_hashes:
        print("Sample NSEC3 hashes:")
        for h in sorted(nsec3_hashes):
            print(h)
        print("(NSEC3 is enabled; offline zone cracking is possible.)")
    else:
        print(f"{BLUE}No NSEC3 records found for {domain}.{RESET}")

def check_srv(domain):
    print(f"\n=== SRV record check for {domain} ===")
    srv_services = ["_imap", "_imaps", "_pop3", "_pop3s", "_smtp", "_smtps",
                    "_submission", "_caldav", "_ldap", "_carddav", "_xmpp-client",
                    "_xmpp-server", "_http", "_https", "_radius", "_radsec", "_kerberos",
                    "_minecraft", "_sip", "_sips", "_kpasswd", "_ftp", "_jabber", "_h323cs",
                    "_h323ls", "_nfs"]
    found = False
    for srv in srv_services:
        name = f"{srv}._tcp.{domain}"
        url = "https://cloudflare-dns.com/dns-query"
        params = {"name": name, "type": "SRV"}
        data = fetch_json(url, params)
        if data and "Answer" in data and len(data["Answer"]) > 0:
            found = True
            for ans in data["Answer"]:
                print(f"SRV {name}: {html.unescape(ans.get('data',''))}")
    if not found:
        print(f"{BLUE}No SRV records found for {domain}.{RESET}")

# -------------------------------------------------------------------
# Main function to run all checks

def perform_all_checks(domain):
    root = get_root_domain(domain)
    subdomain = domain
    print(f"\nPerforming checks for: {domain}")
    print(f"Root domain: {root}")

    # Basic record checks
    check_record(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", domain, "MX")
    check_record(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT", domain, "SPF")
    check_record(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT", domain, "DMARC")
    check_record(f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS", domain, "NS")
    check_record(f"https://cloudflare-dns.com/dns-query?name={domain}&type=DNSKEY", domain, "DNSSEC")
    check_record(f"https://cloudflare-dns.com/dns-query?name=_mta-sts.{domain}&type=TXT", domain, "MTA-STS")
    check_record(f"https://cloudflare-dns.com/dns-query?name=_smtp._tls.{domain}&type=TXT", domain, "SMTP TLS Reporting")
    check_record(f"https://cloudflare-dns.com/dns-query?name=_adsp._domainkey.{domain}&type=TXT", domain, "ADSP")

    mta_sts_text = fetch_mta_sts(domain)
    if mta_sts_text:
        print(f"MTA-STS text:\n{mta_sts_text}")
    else:
        print(f"{BLUE}No MTA-STS text file found for {domain}.{RESET}")

    # DKIM and ARC
    check_dkim(domain)
    check_arc(domain)
    # DANE
    check_dane(domain)
    # NSEC and NSEC3
    check_nsec(domain)
    check_nsec3(domain)
    # SRV records
    check_srv(domain)

def main():
    if len(sys.argv) < 2:
        print("Usage: mailfail_full.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip()
    perform_all_checks(domain)
    print(f"\nTotal warnings (badge count): {badge}")

if __name__ == "__main__":
    main()
