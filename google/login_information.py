# Functions used to extract for each domain some information
# The collected data is used by the crawler to login

import traceback
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tinydb import TinyDB, Query
from utility.utility import read_json, get_tld
from utility.facebook import is_facebook_login, get_facebook_base_url
from driver import Driver
import re
import time

db = TinyDB("data/_facebook-01.json", indent=4)


# Extract the XPath of a candidate Facebook login button
def get_facebook_button(element, keyword="facebook"):
    # Check if the button contains a Facebook link unrelated to login
    href = element.attrs.get("href", None)
    if href and href.startswith("https://www.facebook.com") and not is_facebook_login(href):
        return None

    keyword = keyword.lower()
    tag = element.name
    # Check if the element contains the keyword in the id
    if element.has_attr("id") and keyword in element["id"].lower():
        return f"//{tag}[@id='{element['id']}']"

    # Check if the element contains the keyword in a class
    if element.has_attr("class"):
        classes = element["class"]
        for class_ in [x for x in classes if keyword in x.lower()]:
            if len(classes) > 1:
                return f"//{tag}[contains(@class, '{class_}')]"
            return f"//{tag}[@class='{class_}']"

    # Check if the keyword is contained in another attribute
    for attribute in element.attrs.items():
        if keyword in attribute[1]:
            return f"//{tag}[@{attribute[0]}='{attribute[1]}']"

    # Check if the keyword is contained in the element text
    if keyword in element.text.lower():
        # Extract the exact representation of the keyword (case sensitive)
        term = re.search(keyword, element.text, re.IGNORECASE).group(0)
        return f"//*[text()[contains(.,'{term}')]]//ancestor::{tag}"


def get_facebook_buttons(login_url):
    driver = Driver(headless=False)
    try:
        # Open the page with Selenium
        driver.get(login_url)
        time.sleep(5)

        # Analyze the code with BeautifulSoup
        soup = BeautifulSoup(driver.page_source, "html.parser")
        tags = soup.find_all(["a", "button", "input"])
        candidates = []

        # Get the candidate Facebook buttons
        for tag in tags:
            xpath = get_facebook_button(tag)
            if xpath:
                candidates.append(xpath)
        return candidates
    except:
        print("Error extracting information from login page")
        print(traceback.format_exc(), file=sys.stderr)
    finally:
        driver.quit()


# Extract information useful for the Facebook login
def get_facebook_data(login_url):
    driver = Driver(headless=True)
    try:
        # Open the page with Selenium
        driver.get(login_url)
        # time.sleep(5)

        # Analyze the code with BeautifulSoup
        soup = BeautifulSoup(driver.page_source, "html.parser")
        tags = soup.find_all(["a", "button", "input"])
        idp = {
            "name": "facebook.com",
            "direct": False,
            "internal": None,
            "button": None
        }

        # Get all the links of the page, search for the presence of a direct link
        urls = [x["href"] for x in soup.find_all(href=True)]
        for url in urls:
            if is_facebook_login(url):
                idp["direct"] = True
                return idp

        # Check if an element contains an internal Facebook page
        for tag in tags:
            if tag.has_attr("href") and "facebook" in tag["href"]:
                href = tag["href"]
                if not bool(urlparse(href).netloc):
                    # TODO: Why not current_url instead?
                    # Due to redirects, login_url can be different
                    href = urljoin(login_url, href)
                if not urlparse(href).scheme:
                    href = f"https://{href}"
                if get_tld(login_url) == get_tld(href):
                    idp["internal"] = href
                    return idp

        # Get a candidate Facebook button
        for tag in tags:
            xpath = get_facebook_button(tag)
            if xpath:
                idp["button"] = xpath
                return idp
        return None
    except:
        print("Error extracting information from login page")
        print(traceback.format_exc(), file=sys.stderr)
    finally:
        driver.quit()


# Create a database to store the domains data
def create_database(source):
    for domain in read_json(source):
        if not db.contains(Query().domain == domain["domain"]):
            db.insert(domain)


# Add the login information for each domain
def add_facebook_login_information():
    # Get the domains without a Facebook login defined
    domains = db.search(~Query().idps.any((Query().name == "facebook.com")))
    for domain in domains:
        print(f"\n[{domain.doc_id}] {domain['domain']}")
        facebook = get_facebook_data(domain["login"])
        if facebook:
            domain["idps"] = [facebook]
            db.update(domain, doc_ids=[domain.doc_id])
            print(facebook)


# Analyze the domains login
def analyze(filename):
    facebook_count = 0
    direct, internal, button = 0, 0, 0
    domains = read_json(filename)
    for domain in domains:
        providers = domain.get("identity_providers", [])
        idp = next((x for x in providers if x["name"] == "facebook.com"), None)
        if idp:
            facebook_count += 1
            direct += 1 if idp["direct"] else 0
            internal += 1 if idp["internal"] else 0
            button += 1 if idp["button"] else 0
    print(f"\nNumber of domains: {len(domains)}")
    print(f"Number of Facebook domains: {facebook_count}")
    print(f"Login [direct: {direct}, internal: {internal}, button: {button}]")


# Analyze the type of Facebook login
def analyze_facebook_login_type(database):
    domains = database.search(Query().idps.any((Query().name == "facebook.com")))
    facebook = [y for x in domains for y in x["idps"] if y["name"] == "facebook.com"]
    print(f"Number of domains: {len(database.all())}")
    print(f"Number of Facebook domains: {len(domains)}")
    print(f"\nDirect: {len([x for x in facebook if x['direct']])}")
    print(f"Internal: {len([x for x in facebook if x['internal']])}")
    print(f"Button: {len([x for x in facebook if x['button']])}")


# Extract the domains with Facebook from the source file
def extract_facebook_domains():
    database = TinyDB("data/_facebook-02.json", indent=4)
    for item in read_json("source-02"):
        if not database.contains(Query().domain == item["site"]):
            domain = {"domain": item["site"], "login": None}
            for idp in item["idps"]:
                # Get the Facebook identity provider from the list
                if get_facebook_base_url(idp.get("idp_landing_url", "")):
                    internal = idp["idp_url"] if get_tld(idp["idp_url"]) != "facebook.com" else None
                    domain["idps"] = [{
                        "name": "facebook.com",
                        "direct": not internal,
                        "internal": internal,
                        "button": None,
                        "url": get_facebook_base_url(idp.get("idp_landing_url", ""))
                    }]
                    database.insert(domain)
                    break


def main():
    print("Add Facebook login information")
    create_database("source-01")
    add_facebook_login_information()
    # database = TinyDB("data/facebook-01.json", indent=4)
    # analyze_facebook_login_type(database)
    # extract_facebook_domains()


if __name__ == "__main__":
    main()
