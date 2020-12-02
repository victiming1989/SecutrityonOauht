import json
from tldextract import extract
from urllib.parse import parse_qs, urlparse, urlencode
import csv
import random


# Read the given JSON file
def read_json(filename):
    with open(f"data/{filename}.json", encoding="utf-8") as file:
        return json.load(file)


# Save the object in a JSON file
def save_json(obj, filename):
    with open(f"data/{filename}.json", "w", encoding="utf-8") as file:
        json.dump(obj, file, indent=4)


# Get the list of domains with errors
def get_errors(filename):
    with open(f"data/errors/{filename}_errors.csv") as file:
        csv_reader = csv.reader(file)
        return [row[0] for row in csv_reader]


# Extract the top level domain
def get_tld(url):
    tsd, td, tsu = extract(url)
    return f"{td}.{tsu}"


# Get the login type for the domain
def get_login_type(idp):
    if idp["internal"]:
        return "internal"
    return "button" if idp["button"] else "direct"


# Get the IdP information for the domain
def get_idp(domain, idp_name):
    return next(iter([x for x in domain.get("idps", []) if x["name"] == idp_name]), None)


# Get the value of the given parameter from the URL
def get_parameter(url, parameter):
    param = parse_qs(urlparse(url).query).get(parameter)
    return param[0] if param else ""


# Replace the value of the given parameter
def replace_parameter(url, parameter, value):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if query.get(parameter):
        query[parameter][0] = value
        parsed = parsed._replace(query=urlencode(query, doseq=True))
    return parsed.geturl()


# Remove the parameter with the given name
def remove_parameter(url, parameter):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query.pop(parameter, None)
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return parsed.geturl()


# Get a different random permutation for the given string
def get_random_permutation(string):
    if len(set(string)) > 1:
        while True:
            permutation = "".join(random.sample(string, len(string)))
            if permutation != string:
                return permutation
