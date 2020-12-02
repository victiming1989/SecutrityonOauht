from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from driver import Driver
from domain import FacebookDomains
from tinydb import TinyDB, Query
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

alexa = TinyDB("data/alexa.json", indent=4)


# Get the Alexa topsites rank for the given domain
def get_alexa_rank(driver, domain):
    try:
        # Open the Alexa page and wait until the rank cards is loaded
        driver.get(f"https://www.alexa.com/siteinfo/{domain['domain']}")
        has_rank = ec.presence_of_element_located((By.ID, "card_rank"))
        page = WebDriverWait(driver, 10).until(has_rank)

        # Extract the rank information and return it
        rank = page.find_elements_by_xpath("//div[@id='card_rank']//*[contains(@class, 'data')]")
        return int("".join(filter(lambda x: x.isdigit(), rank[0].text))) if len(rank) else 0
    except Exception as e:
        print(e)
        return 0


# Get the Alexa topsites rank for the given domains
def get_alexa_ranks(domains, update=False):
    driver = Driver(headless=True)
    for domain in domains:
        name = domain["domain"]
        if not alexa.search(Query().domain == name) or update:
            rank = get_alexa_rank(driver, domain)
            if rank:
                alexa_domain = {"domain": name, "rank": rank}
                alexa.upsert(alexa_domain, Query().domain == name)
                print(alexa_domain)
    driver.quit()


# Show the information obtained from the Alexa Topsites service
def print_alexa_information():
    vulnerable_domains = [x["domain"] for x in FacebookDomains().get_vulnerables()]
    domains, vulnerable = defaultdict(int), defaultdict(int)
    classes = [1, 1000, 10000, float("inf")]
    for domain in alexa.all():
        if domain["rank"] > 0:
            rank_class = max([x for x in classes if domain["rank"] >= x])
            rank_interval = f"{rank_class}-{classes[classes.index(rank_class) + 1]}"

            domains[rank_interval] += 1
            if domain["domain"] in vulnerable_domains:
                vulnerable[rank_interval] += 1

    sorted_domains = sorted(domains.items(), key=lambda kv: kv[0])
    sorted_vulnerable = sorted(vulnerable.items(), key=lambda kv: kv[0])

    # Create a plot to show the rank data
    labels, values1 = zip(*[(x[0], x[1]) for x in sorted_domains])
    values2 = [x[1] for x in sorted_vulnerable]
    plot_alexa_rank(labels, values1, values2)


# Plot the Alexa Topsites rank information
def plot_alexa_rank(labels, domains, vulnerable):
    figure, ax = plt.subplots(1, 1, figsize=(6, 5))

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
    ax.set_xlabel("Alexa Rank")
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
    figure.savefig("figures/alexa_ranks.png", format="png")
    figure.savefig("figures/alexa_ranks.eps", format="eps")
    plt.show()


def main():
    # database = FacebookDomains()
    # domains = database.get_attack_domains()
    # get_alexa_ranks(domains)
    print_alexa_information()


if __name__ == "__main__":
    main()
