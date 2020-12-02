from urllib.parse import parse_qs, urlparse
from utility.utility import get_idp, get_parameter, get_attacks
from bs4 import BeautifulSoup
import requests
import traceback
import re
import sys


# Check if the URL leads to the Facebook login page
def is_facebook_login(url):
    pattern = "https://www\.facebook\.com/((v\d*\.?\d*/)?dialog/oauth|login\.php|login/reauth\.php).*"
    return re.match(pattern, url.lower())


# Get the Facebook information for the domain
def get_facebook(domain):
    return get_idp(domain, "facebook.com")


# Find a Facebook login URL in page
def get_facebook_login(html):
    soup = BeautifulSoup(html, "html.parser")
    urls = [x["href"] for x in soup.find_all(href=True)]
    return next(iter([x for x in urls if is_facebook_login(x)]), None)


# Get the cleaned Facebook login URL
def get_facebook_url(url):
    pattern = "https://www\.facebook\.com/(login\.php|login/reauth\.php).*"
    if re.match(pattern, url.lower()):
        # Extract the authorization endpoint URL from the next parameter
        next_url = parse_qs(urlparse(url).query).get("next")
        url = next_url[0] if next_url else ""
    if is_facebook_login(url):
        return url


# Get information about the app with the given id
def get_facebook_application(application_id):
    try:
        url = f"https://graph.facebook.com/{application_id}"
        response = requests.get(url).json()
        if not response.get("error"):
            return response
    except:
        print(f"ERROR Getting the Facebook application info")
        print(traceback.format_exc(), file=sys.stderr)


# Get the type of OAuth flow
def get_flow(url):
    url = get_facebook_url(url)
    return get_parameter(url, "response_type")


# Get the state for the domain
def get_state(domain):
    facebook = get_facebook(domain)
    url = get_facebook_url(facebook.get("authorization_url"))
    return get_parameter(url, "state")


# Get the whole list of states obtained for the domain
def get_states(domain):
    states = []
    facebook = get_facebook(domain)
    for attack in get_attacks():
        url = facebook.get(f"authorization_response_{attack}")
        state = get_parameter(url, "state")
        if state:
            states.append(state)
    return states


# Check if the string is used for the OAuth code flow
def is_code_flow(flow):
    # Handle the case in which 'granted_scopes' is included
    return not flow or any([x for x in flow.split(",") if x.strip() == "code"])


# Get the version of the Graph API
def get_version(domain):
    facebook = get_facebook(domain)
    url = get_facebook_url(facebook.get("authorization_url"))
    pattern = "https://www\.facebook\.com/v(\d*\.?\d*)/dialog/oauth.*"
    result = re.search(pattern, url, re.IGNORECASE)
    if result and result.group(1):
        return float(result.group(1))
    return 0


# Get the value of the display parameter
def get_display(domain):
    facebook = get_facebook(domain)
    url = get_facebook_url(facebook.get("authorization_url"))
    return get_parameter(url, "display")


# Return if the website is vulnerable to the given attacks
def is_vulnerable(domain, attacks=None, to_all=False):
    attacks = attacks or get_attacks()
    facebook = get_facebook(domain)
    vulnerable = [facebook.get(f"vulnerable_{x}") for x in attacks]
    return all(vulnerable) if to_all else any(vulnerable)


# Return the websites vulnerable to the given attacks
def get_vulnerable(domains, attacks=None, to_all=False):
    attacks = attacks or get_attacks()
    return [x for x in domains if is_vulnerable(x, attacks, to_all)]
