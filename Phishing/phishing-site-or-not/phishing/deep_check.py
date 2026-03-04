import sys
import json
import socket
import requests
from bs4 import BeautifulSoup
import tldextract

# optional imports
try:
    import whois
except Exception:
    whois = None

try:
    import dns.resolver
except Exception:
    dns = None


def dns_lookup(domain, resolver_ip=None, timeout=5):
    ips = []
    # try dnspython if available and resolver_ip provided
    if dns is not None and resolver_ip:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = timeout
            r.lifetime = timeout
            answers = r.resolve(domain, "A")
            for a in answers:
                ips.append(a.to_text())
            return ips
        except Exception:
            pass
    # fallback to system resolver
    try:
        info = socket.getaddrinfo(domain, None)
        for item in info:
            ips.append(item[4][0])
        return sorted(set(ips))
    except Exception:
        return []


def whois_info(domain):
    if whois is None:
        return {"available": False, "note": "whois lib not installed"}
    try:
        info = whois.whois(domain)
        return {"available": True, "raw": str(info)}
    except Exception as e:
        return {"available": False, "error": str(e)}


def fetch_html(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return {"status_code": r.status_code, "text": r.text, "history_len": len(r.history)}
    except Exception as e:
        return {"status_code": None, "error": str(e)}


def analyze_html(html, base_domain):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    forms = []
    for f in soup.find_all("form"):
        action = f.get('action') or ''
        method = f.get('method') or 'get'
        inputs = [{'type': i.get('type','text'), 'name': i.get('name')} for i in f.find_all('input')]
        forms.append({'action': action, 'method': method.lower(), 'inputs': inputs})
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    external_links = [l for l in links if l.startswith('http') and base_domain not in l]
    images = [img.get('src') for img in soup.find_all('img', src=True)]
    password_fields = sum(1 for f in soup.find_all('input', {'type': 'password'}))

    keywords = ['login','verify','secure','account','confirm','update','authenticate']
    keyword_hits = {k: (k in (title.lower())) for k in keywords}

    suspicious_forms = [f for f in forms if any(inp['type']=='password' for inp in f['inputs'])]

    return {
        'title': title,
        'forms_count': len(forms),
        'suspicious_forms': suspicious_forms,
        'external_links_count': len(external_links),
        'images_count': len(images),
        'password_fields': password_fields,
        'keyword_hits_in_title': keyword_hits,
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error":"No URL provided"}))
        return
    url = sys.argv[1]
    ext = tldextract.extract(url)
    domain = ext.registered_domain or (ext.domain + "." + ext.suffix)

    out = {"url": url, "domain": domain}

    out['dns_system'] = dns_lookup(domain)
    out['dns_google'] = dns_lookup(domain, resolver_ip='8.8.8.8')
    out['dns_cloudflare'] = dns_lookup(domain, resolver_ip='1.1.1.1')

    out['whois'] = whois_info(domain)

    fetched = fetch_html(url)
    out['http'] = {k: fetched.get(k) for k in ['status_code','history_len','error']}

    if fetched.get('text'):
        out['analysis'] = analyze_html(fetched['text'], domain)
    else:
        out['analysis'] = {"note":"no content fetched"}

    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
