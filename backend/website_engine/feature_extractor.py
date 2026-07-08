from urllib.parse import urlparse
import re

def get_url_length(url):
    return len(url)

def get_domain_length(url):
    domain = urlparse(url).netloc
    return len(domain)

def count_dots(url):
    return url.count(".")

def count_hyphens(url):
    return url.count("-")

def count_digits(url):
    return sum(char.isdigit() for char in url)

def has_https(url):
    return url.startswith("https://")

def has_ip_address(url):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return bool(re.search(pattern, url))

def count_at_symbol(url):
    return url.count("@")

def count_subdomains(url):
    domain = urlparse(url).netloc
    return max(0, domain.count(".") - 1)


