from tinydb import TinyDB, Query
from utility.facebook import is_code_flow, get_facebook_base_url
from utility.google import get_google_base_url
from utility.utility import get_parameter
from random import shuffle


class Domains(TinyDB):

    FACEBOOK = "facebook.com"
    GOOGLE = "google.com"

    def __init__(self, filename):
        TinyDB.__init__(self, f"data/{filename}.json", indent=4)

    # Get the domain with the given name
    def get_domain(self, name):
        return self.get(Query().domain == name)

    # Get the IdP information for the domain
    @staticmethod
    def get_idp_info(domain, idp_name):
        return next(iter([x for x in domain.get("idps", []) if x["name"] == idp_name]), None)


class FacebookDomains(Domains):

    BASE = (Query().name == "facebook.com") & (Query().registration_error == False)
    AUTH_URL = Query().authorization_url
    MARKER_URL = Query().marker_url & (Query().marker_url != None)
    CODE_FLOW = Query().oauth_flow & (Query().oauth_flow.test(lambda x: is_code_flow(x)))
    AUTH_ERR = Query().authorization_error & (Query().authorization_error != None)
    MARKER = Query().marker & (Query().marker != None)
    AUTH_RESP = Query().authorization_response
    VULNERABLE_1 = Query().vulnerable_1
    VULNERABLE_2 = Query().vulnerable_2
    VULNERABLE_3 = Query().vulnerable_3
    VULNERABLE_1v = Query().vulnerable_1v
    EMPTY_STATE = Query().authorization_url.test(lambda x: get_parameter(get_facebook_base_url(x), "state") == "")

    ATTACK_DOMAINS = BASE & AUTH_URL & CODE_FLOW & ~AUTH_ERR & MARKER

    def __init__(self, filename="facebook"):
        Domains.__init__(self, filename)

    def has(self, _property, value=None):
        property_value = Query()[_property] == value if value else Query()[_property] != None
        return Query()[_property] & property_value

    def has_not(self, _property, value=None):
        return ~(self.has(_property, value))

    # Get the Facebook information for the domain
    def get_facebook_info(self, domain):
        return self.get_idp_info(domain, self.FACEBOOK)

    def get_all(self):
        return self.search(Query().idps.any(self.BASE))

    def get_marker_url(self):
        return self.search(Query().idps.any(self.BASE & self.MARKER_URL))

    def get_incomplete(self):
        return self.search(Query().idps.any(self.BASE & ~self.AUTH_URL))

    def get_login(self, user=None):
        domains = self.search(Query().idps.any(self.ATTACK_DOMAINS))
        filtered = []
        if user:
            marker = f"{user.name}_marker"
            for domain in domains:
                facebook = self.get_facebook_info(domain)
                if marker not in facebook or not facebook.get(marker):
                    filtered.append(domain)
            domains = filtered
        return domains

    def get_attack(self, state=None, remove=None):

        if state is None:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS))
        condition = ~self.EMPTY_STATE if state else self.EMPTY_STATE
        return self.search(Query().idps.any(self.ATTACK_DOMAINS & condition))

    def get_login_domains(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & self.CODE_FLOW))

    def get_no_code_flow(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & ~self.CODE_FLOW))

    def get_registration_errors(self):
        return self.search(Query().idps.any(Query().registration_error == True))

    def get_authorization_errors(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & self.CODE_FLOW & self.AUTH_ERR))

    def get_login_incomplete(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & self.CODE_FLOW & ~self.AUTH_ERR & ~self.MARKER))

    def get_attack_domains_old(self, with_state=False):
        if with_state:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS & ~self.EMPTY_STATE))
        return self.search(Query().idps.any(self.ATTACK_DOMAINS))

    def get_attack_domains(self, state=None):
        if state is None:
            domains = self.search(Query().idps.any(self.ATTACK_DOMAINS))
        else:
            condition = ~self.EMPTY_STATE if state else self.EMPTY_STATE
            domains = self.search(Query().idps.any(self.ATTACK_DOMAINS & condition))
        shuffle(domains)
        return domains

    def get_attack_incomplete(self, attack_name, with_state=False):
        attack = f"vulnerable_{attack_name}"
        missing_vulnerable = (~(Query()[attack]) | (Query()[attack] == None))
        if with_state:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS & ~self.EMPTY_STATE & missing_vulnerable))
        return self.search(Query().idps.any(self.ATTACK_DOMAINS & missing_vulnerable))

    def get_vulnerable(self, attack_name):
        attack = f"vulnerable_{attack_name}"
        return self.search(Query().idps.any(self.BASE & Query()[attack] & (Query()[attack] == True)))

    # Return the websites vulnerable to the given attacks
    def get_vulnerables(self, attacks="0,1,2,3,0v,1v,2v,3v"):
        vulnerable = []
        for domain in self.get_attack_domains():
            facebook = self.get_facebook_info(domain)
            if any([facebook.get(f"vulnerable_{x}") for x in attacks.split(",")]):
                vulnerable.append(domain)
        return vulnerable

    def get_not_vulnerable(self, attacks="0,1,2,3,0v,1v,2v,3v"):
        not_vulnerable = []
        for domain in self.get_attack_domains():
            facebook = self.get_facebook_info(domain)
            if not any([facebook.get(f"vulnerable_{x}") for x in attacks.split(",")]):
                not_vulnerable.append(domain)
        return not_vulnerable

    # Save a new value attribute for the domain
    def save_value(self, domain, key, value, overwrite=True):
        facebook_info = self.get_facebook_info(domain)
        if overwrite or not facebook_info.get(key):
            facebook_info[key] = value
            self.update(domain, doc_ids=[domain.doc_id])

    def delete_facebook_key(self, key):
        for domain in self.get_all():
            facebook = self.get_facebook_info(domain)
            if key in facebook:
                del facebook[key]
                self.update(domain, doc_ids=[domain.doc_id])

    # Look for the presence of markers in the page source
    @staticmethod
    def get_marker(source, markers):
        text = str(source).lower()
        for marker in markers:
            if marker in text:
                return marker


class GoogleDomains(Domains):

    BASE = (Query().name == "google.com") # & (Query().registration_error == False)
    AUTH_URL = Query().authorization_url
    MARKER_URL = Query().marker_url & (Query().marker_url != None)
    CODE_FLOW = Query().oauth_flow & (Query().oauth_flow.test(lambda x: is_code_flow(x)))
    AUTH_ERR = Query().authorization_error #& (Query().authorization_error != None)
    MARKER = Query().marker & (Query().marker != None)
    AUTH_RESP = Query().authorization_response
    VULNERABLE_1 = Query().vulnerable_1
    VULNERABLE_2 = Query().vulnerable_2
    VULNERABLE_3 = Query().vulnerable_3
    VULNERABLE_1v = Query().vulnerable_1v
    EMPTY_STATE = Query().authorization_url.test(lambda x: get_parameter(get_google_base_url(x), "state") == "")

    ATTACK_DOMAINS = BASE & AUTH_URL & CODE_FLOW & ~AUTH_ERR & MARKER

    def __init__(self, filename="google"):
        Domains.__init__(self, filename)

    def has(self, _property, value=None):
        property_value = Query()[_property] == value if value else Query()[_property] != None
        return Query()[_property] & property_value

    def has_not(self, _property, value=None):
        return ~(self.has(_property, value))

    # Get the Google information for the domain
    def get_google_info(self, domain):
        return self.get_idp_info(domain, self.GOOGLE)

    def get_all(self):
        return self.search(Query().idps.any(self.BASE))

    def get_marker_url(self):
        return self.search(Query().idps.any(self.BASE & self.MARKER_URL))

    def get_incomplete(self):
        return self.search(Query().idps.any(self.BASE & ~self.AUTH_URL))

    def get_login(self, user=None):
        domains = self.search(Query().idps.any(self.ATTACK_DOMAINS))
        filtered = []
        if user:
            marker = f"{user.name}_marker"
            for domain in domains:
                google = self.get_google_info(domain)
                if marker not in google or not google.get(marker):
                    filtered.append(domain)
            domains = filtered
        return domains

    def get_attack(self, state=None, remove=None):

        if state is None:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS))
        condition = ~self.EMPTY_STATE if state else self.EMPTY_STATE
        return self.search(Query().idps.any(self.ATTACK_DOMAINS & condition))

    def get_login_domains(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL))# & self.CODE_FLOW))

    def get_no_code_flow(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & ~self.CODE_FLOW))

    def get_registration_errors(self):
        return self.search(Query().idps.any(Query().registration_error == True))

    def get_authorization_errors(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & self.CODE_FLOW & self.AUTH_ERR))

    def get_login_incomplete(self):
        return self.search(Query().idps.any(self.BASE & self.AUTH_URL & self.CODE_FLOW & ~self.AUTH_ERR & ~self.MARKER))

    def get_attack_domains_old(self, with_state=False):
        if with_state:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS & ~self.EMPTY_STATE))
        return self.search(Query().idps.any(self.ATTACK_DOMAINS))

    def get_attack_domains(self, state=None):
        if state is None:
            domains = self.search(Query().idps.any(self.ATTACK_DOMAINS))
        else:
            condition = ~self.EMPTY_STATE if state else self.EMPTY_STATE
            domains = self.search(Query().idps.any(self.ATTACK_DOMAINS & condition))
        shuffle(domains)
        return domains

    def get_attack_incomplete(self, attack_name, with_state=False):
        attack = f"vulnerable_{attack_name}"
        missing_vulnerable = (~(Query()[attack]) | (Query()[attack] == None))
        if with_state:
            return self.search(Query().idps.any(self.ATTACK_DOMAINS & ~self.EMPTY_STATE & missing_vulnerable))
        return self.search(Query().idps.any(self.ATTACK_DOMAINS & missing_vulnerable))

    def get_vulnerable(self, attack_name):
        attack = f"vulnerable_{attack_name}"
        return self.search(Query().idps.any(self.BASE & Query()[attack] & (Query()[attack] == True)))

    # Return the websites vulnerable to the given attacks
    def get_vulnerables(self, attacks="0,1,2,3,0v,1v,2v,3v"):
        vulnerable = []
        for domain in self.get_attack_domains():
            google = self.get_google_info(domain)
            if any([google.get(f"vulnerable_{x}") for x in attacks.split(",")]):
                vulnerable.append(domain)
        return vulnerable

    def get_not_vulnerable(self, attacks="0,1,2,3,0v,1v,2v,3v"):
        not_vulnerable = []
        for domain in self.get_attack_domains():
            google = self.get_google_info(domain)
            if not any([google.get(f"vulnerable_{x}") for x in attacks.split(",")]):
                not_vulnerable.append(domain)
        return not_vulnerable

    # Save a new value attribute for the domain
    def save_value(self, domain, key, value, overwrite=True):
        google_info = self.get_google_info(domain)
        if overwrite or not google_info.get(key):
            google_info[key] = value
            self.update(domain, doc_ids=[domain.doc_id])

    def delete_google_key(self, key):
        for domain in self.get_all():
            google = self.get_google_info(domain)
            if key in google:
                del google[key]
                self.update(domain, doc_ids=[domain.doc_id])

    # Look for the presence of markers in the page source
    @staticmethod
    def get_marker(source, markers):
        text = str(source).lower()
        for marker in markers:
            if marker in text:
                return marker
