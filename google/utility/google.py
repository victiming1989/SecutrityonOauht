from urllib.parse import parse_qs, urlparse
from utility.utility import get_idp, get_parameter
from bs4 import BeautifulSoup
import requests
import traceback
import re
import sys


# Check if the URL leads to the Google login page
def is_google_login(url):
    pattern = "https://accounts\.google\.com/(signin/|o/oauth\d*/|servicelogin).*"
    return re.match(pattern, url.lower())


# Get the Google information for the domain
def get_google(domain):
    return get_idp(domain, "google.com")


# Find a Google login URL in page
def get_google_login(html):
    soup = BeautifulSoup(html, "html.parser")
    urls = [x["href"] for x in soup.find_all(href=True)]
    return next(iter([x for x in urls if is_google_login(x)]), None)


# Get the cleaned Google login URL
def get_google_base_url(url):
    #print (url)
   if "accounts.google" in url:
     pattern = "https://accounts\.google\.com/(signin/|o/oauth\d*/|servicelogin).*"
     if re.match(pattern, url.lower()):
        return url


# Get the state for the domain
def get_state(domain):
    google = get_google(domain)
    url = get_google_base_url(google.get("authorization_url"))
    return get_parameter(url, "state")

# Get the type of OAuth flow
def get_flow(url):
    url = get_google_base_url(url)
    return get_parameter(url, "response_type")


# Check if the string is used for the OAuth code flow
def is_code_flow(flow):
    # Handle the case in which 'granted_scopes' is included
    return not flow or any([x for x in flow.split(",") if x.strip() == "code"])


# Get the version of the Graph API
def get_version(url):
    url = get_google_base_url(url)
    pattern = "https://accounts\.google\.com/(signin/|o/oauth\d*/|ServiceLogin).*"
    result = re.search(pattern, url, re.IGNORECASE)
    if result and result.group(1):
        return result.group(1)
    return ""
