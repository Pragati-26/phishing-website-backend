import numpy as np
import re
import socket
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    def having_IP_Address(url):
        match = re.search(r'(\d{1,3}\.){3}\d{1,3}', url)
        return 1 if match else -1

    def URL_Length(url):
        return 1 if len(url) < 54 else 0 if 54 <= len(url) <= 75 else -1

    def Shortining_Service(url):
        shortening_services = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|bitly|is\.gd|buff\.ly"
        return 1 if re.search(shortening_services, url) else -1

    def having_At_Symbol(url):
        return -1 if "@" in url else 1

    def double_slash_redirecting(url):
        return -1 if url.find("//", 7) != -1 else 1

    def Prefix_Suffix(hostname):
        return -1 if "-" in hostname else 1

    def having_Sub_Domain(url):
        dots = urlparse(url).hostname.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1

    def SSLfinal_State(url):
        return 1 if url.startswith("https") else -1

    def Domain_registeration_length(domain):
        try:
            w = whois.whois(domain)
            if w.expiration_date and w.creation_date:
                # Handle list cases returned by whois
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                create = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if (exp - create).days >= 365:
                    return 1
        except Exception:
            pass
        return -1

    def age_of_domain(domain):
        try:
            w = whois.whois(domain)
            if w.creation_date:
                create = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age = (np.datetime64('today') - np.datetime64(create)).astype(int)
                if age >= 180:
                    return 1
        except Exception:
            pass
        return -1

    def web_traffic(domain):
        try:
            alexa_url = f"https://data.alexa.com/data?cli=10&dat=s&url={domain}"
            r = requests.get(alexa_url, timeout=3)
            soup = BeautifulSoup(r.content, "xml")
            rank_tag = soup.find("REACH")
            if rank_tag and int(rank_tag['RANK']) < 100000:
                return 1
        except Exception:
            pass
        return -1

    # Simplified HTML-based features
    def Favicon(url):
        try:
            response = requests.get(url, timeout=3)
            soup = BeautifulSoup(response.text, "html.parser")
            icons = soup.find_all("link", rel=lambda x: x and "icon" in x.lower())
            for icon in icons:
                if hostname not in icon.get("href", ""):
                    return -1
        except Exception:
            return -1
        return 1

    def Request_URL(url):
        try:
            response = requests.get(url, timeout=3)
            soup = BeautifulSoup(response.text, "html.parser")
            imgs = soup.find_all("img", src=True)
            total = len(imgs)
            linked = sum(1 for img in imgs if hostname in img['src'])
            return 1 if total == 0 or linked / total >= 0.5 else -1
        except Exception:
            return -1

    def Submitting_to_email(url):
        return -1 if "mail()" in url or "mailto:" in url else 1

    # Basic heuristics / placeholders
    def Abnormal_URL(): return 1
    def Redirect(url): return -1 if url.count("//") > 1 else 1
    def on_mouseover(): return 1
    def RightClick(): return 1
    def popUpWidnow(): return 1
    def Iframe(): return 1
    def DNSRecord(): return 1
    def Page_Rank(): return 1
    def Links_pointing_to_page(): return 1
    def URL_of_Anchor(): return 1
    def Links_in_tags(): return 1
    def SFH(): return 1

    # Create feature vector in exact order
    features = [
        having_IP_Address(url),
        URL_Length(url),
        Shortining_Service(url),
        having_At_Symbol(url),
        double_slash_redirecting(url),
        Prefix_Suffix(hostname),
        having_Sub_Domain(url),
        SSLfinal_State(url),
        Domain_registeration_length(hostname),
        Favicon(url),
        Request_URL(url),
        URL_of_Anchor(),
        Links_in_tags(),
        SFH(),
        Submitting_to_email(url),
        Abnormal_URL(),
        Redirect(url),
        on_mouseover(),
        RightClick(),
        popUpWidnow(),
        Iframe(),
        age_of_domain(hostname),
        DNSRecord(),
        web_traffic(hostname),
        Page_Rank(),
        Links_pointing_to_page()
    ]

    return np.array(features).reshape(1, -1)
