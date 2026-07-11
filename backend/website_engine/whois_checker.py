"""
WHOIS Checker Module
--------------------
Extracts WHOIS information for a domain.

Author : Aditya Choudhary
Project: AI-Powered Phishing Website Detection System
"""

import whois
from urllib.parse import urlparse
from datetime import datetime, timezone


class WhoisChecker:

    def __init__(self):
        self.cache = {}

    def extract_domain(self, url):
        """Extract domain from URL"""
        return urlparse(url).netloc.lower()

    def get_whois(self, url):
        """
        Fetch WHOIS data.
        Uses cache so repeated requests are faster.
        """

        domain = self.extract_domain(url)

        if domain in self.cache:
            return self.cache[domain]

        try:
            data = whois.whois(domain)
            self.cache[domain] = data
            return data

        except Exception as e:
            print("WHOIS Error:", e)
            return None

    def _get_first_date(self, value):
        """WHOIS may return a list or a single datetime"""

        if value is None:
            return None

        if isinstance(value, list):
            return value[0]

        return value

    def get_domain_age(self, url):

        data = self.get_whois(url)

        if data is None:
            return None

        creation = self._get_first_date(data.creation_date)

        if creation is None:
            return None

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        else:
            creation = creation.astimezone(timezone.utc)

        today = datetime.now(timezone.utc)

        return (today - creation).days

    def get_days_until_expiry(self, url):

        data = self.get_whois(url)

        if data is None:
            return None

        expiry = self._get_first_date(data.expiration_date)

        if expiry is None:
            return None

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        else:
            expiry = expiry.astimezone(timezone.utc)

        today = datetime.now(timezone.utc)

        return (expiry - today).days

    def get_registrar(self, url):

        data = self.get_whois(url)

        if data is None:
            return "Unknown"

        return data.registrar

    def get_country(self, url):

        data = self.get_whois(url)

        if data is None:
            return "Unknown"

        return data.country

    def get_name_servers(self, url):

        data = self.get_whois(url)

        if data is None:
            return []

        return data.name_servers

    def analyze(self, url):
        """
        Returns complete WHOIS analysis
        """

        return {

            "domain_age_days": self.get_domain_age(url),

            "days_until_expiry": self.get_days_until_expiry(url),

            "registrar": self.get_registrar(url),

            "country": self.get_country(url),

            "name_servers": self.get_name_servers(url)
        }


if __name__ == "__main__":

    checker = WhoisChecker()

    url = "https://github.com"

    result = checker.analyze(url)

    print("\n========== WHOIS REPORT ==========\n")

    for key, value in result.items():
        print(f"{key:25}: {value}")