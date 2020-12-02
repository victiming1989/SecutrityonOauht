from utility.facebook import get_facebook, get_parameter, get_facebook_url, get_facebook_application, get_vulnerable
from domain import FacebookDomains
from tinydb import TinyDB, Query
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

applications = TinyDB("../data/applications.json", indent=4)
database = FacebookDomains("../data/facebook")


# Get the Facebook applications information
def get_facebook_applications(domains, update=False):
    for domain in domains:
        try:
            name = domain["domain"]
            if not applications.search(Query().domain == name) or update:
                # Get the authorization URL
                facebook = get_facebook(domain)
                url = get_facebook_url(facebook.get("authorization_url"))

                # Get information about the application
                app_id = get_parameter(url, "client_id")
                application = get_facebook_application(app_id)
                if application:
                    app_domain = {"domain": name, "application": application}
                    applications.upsert(app_domain, Query().domain == name)
                    print(app_domain)
        except Exception as e:
            print(e)


def print_information(limit=6):
    attack_domains = database.get_attack_domains()
    vulnerable_domains = [x["domain"] for x in get_vulnerable(attack_domains)]
    domains, vulnerable = defaultdict(int), defaultdict(int)

    for domain in applications.all():
        category = domain["application"].get("category")
        domains[category] += 1
        if domain["domain"] in vulnerable_domains:
            vulnerable[category] += 1

    labels = [x[0] for x in sorted(domains.items(), key=lambda kv: kv[1], reverse=True)][:limit-1]
    values1 = [domains[x] for x in labels]
    values2 = [vulnerable[x] for x in labels]

    # Include the remaining data
    labels.append("Other")
    values1.append(len(attack_domains) - sum(values1))
    values2.append(len(vulnerable_domains) - sum(values2))

    # Create a plot to show the data
    plot_data(labels, values1, values2)


def plot_data(labels, domains, vulnerable):
    figure, ax = plt.subplots(1, 1, figsize=(7, 5))

    ax.spines["right"].set_color(None)
    ax.spines["top"].set_color(None)
    ax.set_axisbelow(True)
    ax.tick_params(which="major", direction="in", length=5)
    plt.grid(axis="y", color="#dddddd")

    x = np.arange(len(labels))
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    width = 0.35

    # Plot the histograms with the buckets data
    r1 = ax.bar(x - width / 2, domains, width, label="Crawled", color="w", edgecolor="k")
    r2 = ax.bar(x + width / 2, vulnerable, width, label="Vulnerable", color="#b2bec3", edgecolor="k")

    # Add labels on the axis and the legend
    ax.set_ylabel("Number of domains")
    ax.set_xlabel("Facebook Application category")
    ax.legend()

    # Attach a text label above each bar, displaying its height
    def auto_label(bars):
        for bar in bars:
            h, w = bar.get_height(), bar.get_width()
            ax.annotate("{}".format(h), xy=(bar.get_x() + w / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom")
    auto_label(r1)
    auto_label(r2)

    figure.tight_layout()
    figure.savefig("../figures/applications.png", format="png")
    figure.savefig("../figures/applications.eps", format="eps")
    plt.show()


def main():
    # domains = database.get_attack_domains()
    # get_facebook_applications(domains)
    print_information()


if __name__ == "__main__":
    main()
