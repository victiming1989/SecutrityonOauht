from utility.facebook import get_facebook, get_parameter, get_facebook_base_url, get_facebook_application
from domain import FacebookDomains
from tinydb import TinyDB, Query


applications = TinyDB("data/applications.json", indent=4)
db = FacebookDomains()


# Get the Facebook applications information
def get_facebook_applications(domains, update=False):
    for domain in domains:
        try:
            name = domain["domain"]
            if not applications.search(Query().domain == name) or update:
                # Get the authorization URL
                facebook = get_facebook(domain)
                url = get_facebook_base_url(facebook.get("authorization_url"))

                # Get information about the application
                app_id = get_parameter(url, "client_id")
                application = get_facebook_application(app_id)
                if application:
                    app_domain = {"domain": name, "application": application}
                    applications.upsert(app_domain, Query().domain == name)
                    print(app_domain)
        except Exception as e:
            print(e)


def main():
    domains = db.get_attack_domains()
    get_facebook_applications(domains)


if __name__ == "__main__":
    main()
