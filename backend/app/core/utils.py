import re
import urllib.parse

def get_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]

def is_shortened(url: str) -> int:
    parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    domain = parsed.netloc.lower()
    shorteners = [
        'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 
        'ow.ly', 't.co', 'tinyurl.com', 'tr.im', 'is.gd', 
        'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc',
        'cutt.ly', 'rb.gy', 'shorturl.at'
    ]
    return -1 if domain in shorteners else 1

