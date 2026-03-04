import sys
import json
import os
import requests
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urljoin, urlparse


def save_html(url, out_dir="reports"):
    os.makedirs(out_dir, exist_ok=True)
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        path = os.path.join(out_dir, f"report_{tldextract.extract(url).registered_domain}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(r.text)
        return {"status_code": r.status_code, "path": path, "history_len": len(r.history), "text": r.text}
    except Exception as e:
        return {"error": str(e)}


def extract_details(html, base_domain):
    soup = BeautifulSoup(html, "html.parser")
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    abs_links = []
    for l in links:
        try:
            abs = urljoin(f"http://{base_domain}", l)
            abs_links.append(abs)
        except:
            pass
    external = [u for u in abs_links if urlparse(u).hostname and base_domain not in urlparse(u).hostname]
    external_domains = {}
    for u in external:
        h = urlparse(u).hostname
        external_domains[h] = external_domains.get(h, 0) + 1

    forms = []
    for f in soup.find_all('form'):
        action = f.get('action') or ''
        action_abs = urljoin(f"http://{base_domain}", action)
        method = (f.get('method') or 'get').lower()
        inputs = []
        for i in f.find_all('input'):
            inputs.append({'name': i.get('name'), 'type': i.get('type','text'), 'value': i.get('value')})
        forms.append({'action': action_abs, 'method': method, 'inputs': inputs})

    return {
        'external_domains_sorted': sorted(external_domains.items(), key=lambda x: x[1], reverse=True)[:30],
        'forms': forms,
        'external_count': len(external),
        'unique_external_domains': len(external_domains),
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error":"No URL provided"}))
        return
    url = sys.argv[1]
    ext = tldextract.extract(url)
    domain = ext.registered_domain or (ext.domain + "." + ext.suffix)

    out = {"url": url, "domain": domain}

    saved = save_html(url)
    out['http_status'] = saved.get('status_code')
    out['saved_path'] = saved.get('path')
    if saved.get('text'):
        details = extract_details(saved['text'], domain)
        out.update(details)
    else:
        out['error'] = saved.get('error')

    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()
