from feature_extractor import *

def analyze_url(url):
    features = {
        "url_length": get_url_length(url),
        "domain_length": get_domain_length(url),
        "dots": count_dots(url),
        "hyphens": count_hyphens(url),
        "digits": count_digits(url),
        "https": has_https(url),
        "ip_address": has_ip_address(url),
        "@ symbols": count_at_symbol(url),
        "subdomains": count_subdomains(url)
    }

    return features


if __name__ == "__main__":
    url = input("Enter URL: ")

    result = analyze_url(url)

    print("\nExtracted Features:\n")

    for key, value in result.items():
        print(f"{key:20}: {value}")