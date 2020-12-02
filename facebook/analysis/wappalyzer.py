from domain import FacebookDomains
from tinydb import TinyDB, Query
import matplotlib.pyplot as plt
import numpy as np
import requests
import json
from collections import defaultdict
from utility.facebook import get_vulnerable

db = TinyDB("../data/wappalyzer.json", indent=4)
database = FacebookDomains("../data/facebook")
api_url = "https://api.wappalyzer.com/lookup/v2/"
api_key = "ADtTcpCiVW7b3bjXvk4gG6pa0OjfISdGxYjQANO8"


def get_data():
    for domain in database.get_attack_domains():
        domain_name = domain["domain"]
        try:
            if not db.search(Query().domain == domain_name):
                url = f"https://{domain_name}"
                response = requests.get(api_url, params={"urls": url}, headers={"x-api-key": api_key})
                if response.ok:
                    wappalyzer = {"domain": domain_name, "wappalyzer": json.loads(response.text)[0]}
                    db.upsert(wappalyzer, Query().domain == domain_name)
                    print(wappalyzer)
                    print(f"{response.headers['wappalyzer-credits-remaining']} remaining credits")
        except Exception as e:
            print(e)


def print_information(limit=10):
    vulnerable_domains = [x["domain"] for x in get_vulnerable(database.get_attack_domains())]
    domains, vulnerable = defaultdict(int), defaultdict(int)

    for domain in db.all():
        technologies = [x for x in domain["wappalyzer"]["technologies"]]
        for technology in technologies:
            is_cms = any([x for x in technology.get("categories") if x.get("name") == "CMS"])
            if is_cms:
                technology = technology["slug"]
                domains[technology] += 1
                if domain["domain"] in vulnerable_domains:
                    vulnerable[technology] += 1

    labels = [x[0] for x in sorted(domains.items(), key=lambda kv: kv[1], reverse=True)][:limit]
    values1 = [domains[x] for x in labels]
    values2 = [vulnerable[x] for x in labels]

    # Create a plot to show the data
    plot_data(labels, values1, values2)


def plot_data(labels, domains, vulnerable):
    figure, ax = plt.subplots(1, 1, figsize=(15, 5))

    ax.spines["right"].set_color(None)
    ax.spines["top"].set_color(None)
    ax.set_axisbelow(True)
    ax.tick_params(which="major", direction="in", length=5)
    plt.grid(axis="y", color="#dddddd")

    x = np.arange(len(labels))
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    width = 0.3

    # Plot the histograms with the buckets data
    r1 = ax.bar(x - width / 2, domains, width, label="Crawled", color="w", edgecolor="k")
    r2 = ax.bar(x + width / 2, vulnerable, width, label="Vulnerable", color="#dddddd", edgecolor="k", hatch="//")

    # Add labels on the axis and the legend
    ax.set_ylabel("Number of domains")
    ax.set_xlabel("Technology")
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
    figure.savefig("../figures/wappalyzer.png", format="png")
    figure.savefig("../figures/wappalyzer.eps", format="eps")
    plt.show()


def main():
    # get_data()
    print_information()


if __name__ == "__main__":
    main()
