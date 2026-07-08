from feature_extractor import *

url = "https://paypal-login-security.xyz/login"

print("URL Length:", get_url_length(url))
print("Domain Length:", get_domain_length(url))
print("Dots:", count_dots(url))
print("Hyphens:", count_hyphens(url))
print("Digits:", count_digits(url))
print("HTTPS:", has_https(url))
print("IP Address:", has_ip_address(url))
print("@ Symbols:", count_at_symbol(url))
print("Subdomains:", count_subdomains(url))