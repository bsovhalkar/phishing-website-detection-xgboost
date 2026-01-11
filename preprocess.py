import socket

def having_ip(domain):
    try:
        socket.inet_aton(domain)
        return 1
    except:
        return -1

def url_length(url):
    return 1 if len(url) < 54 else 0 if len(url) <= 75 else -1

def shortening_service(url):
    services = ['bit.ly','tinyurl','goo.gl']
    return -1 if any(s in url for s in services) else 1

import whois
from datetime import datetime

import ssl
import socket
from urllib.parse import urlparse

def SSLfinal_State(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return -1

        context = ssl.create_default_context()
        with socket.create_connection((parsed.netloc, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.netloc):
                return 1
    except:
        return -1


def Domain_registeration_length(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        age = (expiration - creation).days
        return 1 if age >= 365 else -1
    except:
        return -1

import requests

def Favicon(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "favicon" in r.text.lower() else -1
    except:
        return -1

def port(url):
    parsed = urlparse(url)
    return 1 if parsed.port in [None, 80, 443] else -1

def HTTPS_token(url):
    domain = urlparse(url).netloc
    return -1 if "https" in domain.lower() else 1

from bs4 import BeautifulSoup

def Request_URL(url):
    try:
        domain = urlparse(url).netloc
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        external = 0
        total = 0

        for tag in soup.find_all(["img", "audio", "embed", "iframe"]):
            src = tag.get("src")
            if src:
                total += 1
                if domain not in src:
                    external += 1

        if total == 0:
            return 1

        ratio = external / total
        return 1 if ratio < 0.22 else 0 if ratio <= 0.61 else -1
    except:
        return -1


def URL_of_Anchor(url):
    try:
        domain = urlparse(url).netloc
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        unsafe = 0
        total = 0

        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                total += 1
                if "#" in href or "javascript" in href.lower() or domain not in href:
                    unsafe += 1

        if total == 0:
            return 1

        ratio = unsafe / total
        return 1 if ratio < 0.31 else 0 if ratio <= 0.67 else -1
    except:
        return -1

def Links_in_tags(url):
    try:
        domain = urlparse(url).netloc
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        tags = soup.find_all(["meta", "script", "link"])
        total = len(tags)
        external = sum(1 for t in tags if domain not in str(t))

        if total == 0:
            return 1

        ratio = external / total
        return 1 if ratio < 0.17 else 0 if ratio <= 0.81 else -1
    except:
        return -1

def SFH(url):
    try:
        domain = urlparse(url).netloc
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            if action in ["", None]:
                return -1
            if domain not in action:
                return 0
        return 1
    except:
        return -1

def Submitting_to_email(url):
    try:
        r = requests.get(url, timeout=5)
        return -1 if "mailto:" in r.text.lower() else 1
    except:
        return -1

def Abnormal_URL(url):
    try:
        domain = urlparse(url).netloc
        return -1 if domain not in url else 1
    except:
        return -1

def Redirect(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        return -1 if len(r.history) > 1 else 1
    except:
        return -1

def on_mouseover(url):
    try:
        r = requests.get(url, timeout=5)
        return -1 if "onmouseover" in r.text.lower() else 1
    except:
        return -1

def RightClick(url):
    try:
        r = requests.get(url, timeout=5)
        return -1 if "event.button==2" in r.text.lower() else 1
    except:
        return -1

def popUpWidnow(url):
    try:
        r = requests.get(url, timeout=5)
        return -1 if "window.open" in r.text.lower() else 1
    except:
        return -1

def Iframe(url):
    try:
        r = requests.get(url, timeout=5)
        return -1 if "<iframe" in r.text.lower() else 1
    except:
        return -1


def age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days
        return 1 if age >= 180 else -1
    except:
        return -1


import dns.resolver

def DNSRecord(url):
    try:
        domain = urlparse(url).netloc
        dns.resolver.resolve(domain, 'A')
        return 1
    except:
        return -1


def web_traffic(url):
    try:
        return 1
    except:
        return -1

def Page_Rank(url):
    return 1

def Google_Index(url):
    try:
        query = f"https://www.google.com/search?q=site:{url}"
        r = requests.get(query, headers={"User-Agent":"Mozilla/5.0"})
        return -1 if "did not match any documents" in r.text else 1
    except:
        return -1

def Links_pointing_to_page(url):
    return 1

def Statistical_report(url):
    suspicious = ["paypal", "bank", "secure", "login"]
    return -1 if any(word in url.lower() for word in suspicious) else 1


import pandas as pd
from urllib.parse import urlparse

FEATURE_COLUMNS = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
]

def preprocess(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}

    features['having_IP_Address'] = having_ip(domain)
    features['URL_Length'] = url_length(url)
    features['Shortining_Service'] = shortening_service(url)
    features['having_At_Symbol'] = 1 if '@' not in url else -1
    features['double_slash_redirecting'] = 1 if url.rfind('//') <= 6 else -1
    features['Prefix_Suffix'] = 1 if '-' not in domain else -1

    dots = domain.count('.')
    features['having_Sub_Domain'] = 1 if dots <= 1 else 0 if dots == 2 else -1

    features['SSLfinal_State'] = SSLfinal_State(url)
    features['Domain_registeration_length'] = Domain_registeration_length(url)
    features['Favicon'] = Favicon(url)
    features['port'] = port(url)
    features['HTTPS_token'] = HTTPS_token(url)
    features['Request_URL'] = Request_URL(url)
    features['URL_of_Anchor'] = URL_of_Anchor(url)
    features['Links_in_tags'] = Links_in_tags(url)
    features['SFH'] = SFH(url)
    features['Submitting_to_email'] = Submitting_to_email(url)
    features['Abnormal_URL'] = Abnormal_URL(url)
    features['Redirect'] = Redirect(url)
    features['on_mouseover'] = on_mouseover(url)
    features['RightClick'] = RightClick(url)
    features['popUpWidnow'] = popUpWidnow(url)
    features['Iframe'] = Iframe(url)
    features['age_of_domain'] = age_of_domain(url)
    features['DNSRecord'] = DNSRecord(url)
    features['web_traffic'] = web_traffic(url)
    features['Page_Rank'] = Page_Rank(url)
    features['Google_Index'] = Google_Index(url)
    features['Links_pointing_to_page'] = Links_pointing_to_page(url)
    features['Statistical_report'] = Statistical_report(url)


    df = pd.DataFrame([features])
    df = df[FEATURE_COLUMNS]

    return df
