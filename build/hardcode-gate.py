#!/usr/bin/env python3
"""hardcode-gate.py — refuse a release that carries a real identity or a market default in SHIPPED code.

This is a resale product. Nothing that identifies one operator's world may ship: no server name, no customer
account, no public IP, no domain, no phone number, no email, no "home country" default. The only hosts allowed
are the license/download hosts. The rule was written down long before; on 2026-09-06 a fresh install still
defaulted its home region to two specific countries, and test fixtures carried real customer accounts and the
production server's own IP. A rule that is not enforced at build time is a hope.

Generic on purpose: it does NOT carry a list of past customers (that list would itself be a leak). It flags
   1. public IPv4 literals not covered by build/hardcode-allow.txt (vendor CIDRs, public resolvers);
   2. hostnames whose registrable domain is not in the allow file (license hosts + vendors);
   3. email addresses outside the allow file;
   4. /home/<name> literal paths with a real-looking account name;
   5. a NON-EMPTY default for a home/caution region (config must ship empty).
Exit 0 = clean. Exit 6 = something must not ship; every hit is printed with file:line.
"""
import io, os, re, sys, ipaddress

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = ['index.php', 'index.cgi', 'includes', 'modules', 'bin', 'lang']

# THE RELEASE NOTES SHIP TOO, AND THEY SHIP VERBATIM.
#
# Everything above reaches a licensee obfuscated: comments are stripped, strings are scrambled, so a customer
# name written in a comment never leaves this machine. The release notes are the one artifact that arrives
# exactly as it was typed, and the panel puts them on every licensee's Updates page.
#
# This gate never looked at them. Two releases described a real incident using the real account names it happened
# to, and those notes were served as the stable channel's notes while they were current - one customer's account
# names shown to every other customer. Nothing caught it, because the only file that ships unprotected was the
# only file nobody was checking.
NOTES_GLOB = 'packaging/*.RELEASE-NOTES.txt'
ALLOW_FILE = os.path.join(ROOT, 'build', 'hardcode-allow.txt')

allow_hosts, allow_nets, allow_emails = set(), [], set()
if os.path.isfile(ALLOW_FILE):
    for raw in io.open(ALLOW_FILE, encoding='utf-8'):
        t = raw.split('#', 1)[0].strip()
        if not t: continue
        if '@' in t: allow_emails.add(t.lower())
        elif '/' in t:
            try: allow_nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError: pass
        else: allow_hosts.add(t.lower())

IP_RE    = re.compile(r'(?<![\d.\w])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.\w])')
HOST_RE  = re.compile(r'(?<![\w.$(!)+\-*])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|me|sa|eg|ae|de|fr|uk|us|cloud|dev|app|xyz|site|online|store|shop|tech|info|biz))\b', re.I)
EMAIL_RE = re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', re.I)
HOME_RE  = re.compile(r"['\"/]home/([a-z][a-z0-9_.-]{2,31})(?=/|['\"\s])")
HOME_PLACEHOLDERS = {'user', 'username', 'account', 'acct', 'example', 'cpuser', 'owner', 'someuser', 'demoacct', 'acctone', 'accttwo',
                     # cPanel's own system directories under /home — not accounts
                     'backup', 'virtfs', 'cpeasyapache', 'cprestore', 'cpbackup', 'cpbackuptmp', 'cpmove'}
# Things that LOOK like hosts/IPs but are not: CSS class chains (.a.info{), binary magic, UA versions, chat-id suffixes.
NOISE_RE = re.compile(r'(?:\.[a-z][a-z0-9-]*\.(?:info|ok|err|good|warn|bad|crit|dang|muted)\b)|MaxMind\.com|Chrome/\d+\.\d+\.\d+\.\d+|@c\.us|com\.sa', re.I)
REGION_DEFAULT_RE = re.compile(r"'(protect_regions|caution_regions|home_regions)'\s*=>\s*\[\s*'[A-Z]{2}'")

def is_public(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    if not a.is_global: return False
    return not any(a in n for n in allow_nets)

def registrable(host):
    p = host.lower().split('.')
    if len(p) >= 3 and p[-2] in ('com', 'co', 'org', 'net', 'gov', 'edu') and len(p[-1]) == 2:
        return '.'.join(p[-3:])
    return '.'.join(p[-2:])

def host_allowed(h):
    h = h.lower()
    if h in allow_hosts or registrable(h) in allow_hosts: return True
    # any parent listed in the allow file covers subdomains
    parts = h.split('.')
    return any('.'.join(parts[i:]) in allow_hosts for i in range(len(parts)))

hits = []
def scan(path):
    rel = os.path.relpath(path, ROOT).replace('\\', '/')
    try: text = io.open(path, encoding='utf-8', errors='replace').read()
    except Exception: return
    for n, line in enumerate(text.split('\n'), 1):
        code = line.split('//', 1)[0] if not line.lstrip().startswith(('*', '#')) else ''   # comments may name vendors; code may not name identities
        code = NOISE_RE.sub(' ', code)

        # ADDRESSES ARE CHECKED IN COMMENTS TOO. Naming a vendor in prose is fine and often necessary; writing a
        # real server's address in prose never is. A worked example belongs in the RFC 5737 documentation ranges,
        # which cost nothing to use and cannot identify anybody. This exemption let a customer server's address
        # sit in shipped source inside an explanatory comment, which is exactly the leak the gate exists to stop.
        for m in IP_RE.finditer(NOISE_RE.sub(' ', line)):
            ip = m.group(1)
            if not is_public(ip): continue
            if ip.startswith(('192.0.2.', '198.51.100.', '203.0.113.')): continue      # RFC 5737: for documentation
            # "cPanel 11.138.0.7" is a VERSION, not an address. A gate that blocks a release over one teaches
            # people to reach for --force, and then it is not protecting anything at all.
            if re.search(r'(?:cpanel|version|ver\.?|v)\s*$', line[:m.start()], re.I): continue
            hits.append((rel, n, 'IP', ip, line.strip()[:100]))
        for m in HOST_RE.finditer(code):
            h = m.group(1)
            if h.endswith(('.php', '.js', '.css', '.json', '.txt', '.log', '.db', '.dev')) or re.match(r'^[\d.]+$', h): continue
            if h.lower() in ('example.com', 'example.net', 'example.org', 'site.com', 'domain.com', 'yourdomain.com', 'your-domain.com',
                             'customerdomain.com', 'x.net', 'x.com.x', 'smtp.gmail.com', 'crawl.example.com', 'co.uk'): continue   # UI placeholders / vendor example in a form hint
            if not host_allowed(h): hits.append((rel, n, 'HOST', h, line.strip()[:100]))
        for m in EMAIL_RE.finditer(code):
            e = m.group(0).lower()
            if e in allow_emails or re.search(r'@(example\.|.*\.test$|.*\.invalid$|localhost)', e): continue
            hits.append((rel, n, 'EMAIL', e, line.strip()[:100]))
        for m in HOME_RE.finditer(code):
            nm = m.group(1).lower()
            if nm not in HOME_PLACEHOLDERS and not nm.startswith(('$', 'cpmove-', 'cpmove_')):   # cpmove-<user>.tar.gz is cPanel's archive naming, used as a form hint
                hits.append((rel, n, 'HOME-PATH', '/home/' + m.group(1), line.strip()[:100]))
        for m in REGION_DEFAULT_RE.finditer(code):
            hits.append((rel, n, 'MARKET-DEFAULT', m.group(0), line.strip()[:100]))

for item in SHIPPED:
    full = os.path.join(ROOT, item)
    if os.path.isfile(full): scan(full); continue
    for dp, dn, fn in os.walk(full):
        for f in fn:
            if f.endswith(('.php', '.cgi', '.sh', '.js')): scan(os.path.join(dp, f))

# and the notes, which are prose rather than code — scanned by the same rules, since a name is a name
import glob as _glob
for f in sorted(_glob.glob(os.path.join(ROOT, NOTES_GLOB))):
    scan(f)

if hits:
    print('HARDCODE GATE: %d thing(s) in SHIPPED code must not ship to a resale product:' % len(hits))
    for rel, n, cat, tok, ctx in hits[:80]:
        print('  %-14s %-44s:%-5d %-28s | %s' % (cat, rel, n, tok, ctx))
    if len(hits) > 80: print('  ... %d more' % (len(hits) - 80))
    print('  (a legitimate vendor host/CIDR goes in build/hardcode-allow.txt; an identity is removed)')
    sys.exit(6)
# A gate that cannot check something must not let "clean" read as though it did. Emails, hosts, public
# addresses and /home paths are matchable by shape. A BARE ACCOUNT NAME is not: it looks like any other word,
# and that is precisely what leaked once - a release note describing a real incident using the real account
# names it happened to. Nothing here can catch that, so the line below says so instead of implying otherwise.
print('HARDCODE GATE: clean — no identities, no public IPs outside the vendor allow-list, no market defaults.')
print('  (release notes are scanned too. NOT checkable by pattern: a bare account name in prose — read them before publishing.)')
