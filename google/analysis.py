from utility.utility import get_parameter, get_errors
from domain import FacebookDomains
from utility.facebook import get_facebook_base_url, is_code_flow, get_version, get_facebook, get_state
from collections import Counter
from tabulate import tabulate
import json
from tinydb import TinyDB, Query
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt


db = FacebookDomains()


# Return all the tested attacks
def get_all_attacks():
    return [f"{x}{y}" for x in range(0, 5) for y in ["a", "b", "c"]]


# Return the websites vulnerable to the given attacks
def get_vulnerable(domains, attacks=None):
    attacks = attacks or get_all_attacks()
    vulnerable = []
    for domain in domains:
        facebook = get_facebook(domain)
        if any([facebook.get(f"vulnerable_{x}") for x in attacks]):
            vulnerable.append(domain)
    return vulnerable


# Return the websites vulnerable to the given attacks
def is_vulnerable(domain, attacks=None):
    attacks = attacks or get_all_attacks()
    facebook = get_facebook(domain)
    return any([facebook.get(f"vulnerable_{x}") for x in attacks.split(",")])


# Return the result of the attack for the domain
def get_attack(domain, attack):
    facebook = get_facebook(domain)
    return facebook.get(f"vulnerable_{attack}")


# Clean the list of domains removing the errors
def remove_errors(filename):
    errors = get_errors("registration")
    database = TinyDB(f"data/{filename}.json", indent=4)
    cleaned = TinyDB(f"data/{filename}-cleaned.json", indent=4)
    for domain in database.all():
        # Add the domains without errors
        if domain["domain"] not in errors:
            cleaned.insert(domain)


# Include the registration errors in the database
def add_registration_errors():
    errors = get_errors("registration")
    for domain in db.all():
        has_error = domain["domain"] in errors
        db.save_value(domain, "registration_error", has_error)


# Get the list of state parameters
def get_states(domains):
    return [get_state(x) for x in domains]


# Print the lengths of the state parameters
def print_state_lengths(domains, bins=10):
    states = get_states(domains)
    lengths = [len(x) for x in states if x]

    counter = Counter(lengths)
    print(counter)
    keys = ["0"] + [f"$2^{x}$" for x in range(bins)]
    values = [len([x for x in states if not x])]
    for i in range(bins):
        value = sum([x[1] for x in counter.items() if 2**i <= x[0] < 2**(i+1)])
        print(f"Range {2**i} <= x < {2**(i+1)} => {value}")
        values.append(value)
    more = sum([x[1] for x in counter.items() if x[0] >= 2**bins])
    print(f"Range x >= {2**bins} => {more}")
    values[bins-1] += more
    print(values)
    print(sum(values))

    # Plot the histogram with the buckets data
    plot_state_lengths(keys, values)


# Plot the lengths of the state parameters
def plot_state_lengths(labels, values):
    figure, ax = plt.subplots(1, 1, figsize=(6, 3))

    ax.spines["right"].set_color(None)
    ax.spines["top"].set_color(None)
    ax.set_axisbelow(True)
    ax.tick_params(direction="in", length=5)
    plt.grid(axis="y", color="#dddddd")

    # Plot the histogram with the buckets data
    plt.bar(labels, values, color="w", edgecolor="k", width=0.6)
    ax.set_ylabel("Number of states")
    ax.set_xlabel("Number of characters per state")

    figure.tight_layout()
    figure.savefig("figures/state_length.png", format="png")
    figure.savefig("figures/state_length.eps", format="eps")
    plt.show()


# Print information about Facebook dialog version
def get_api_versions(domains):
    versions, vulnerable = [], []
    for domain in domains:
        facebook = get_facebook(domain)
        version = get_version(facebook.get("authorization_url"))
        if version:
            version = f"v{int(float(version))}"
        versions.append(version)
        if is_vulnerable(domain):
            vulnerable.append(version)

    version_counter = Counter(versions)
    vulnerable_counter = Counter(vulnerable)

    print(version_counter.most_common())
    items = sorted(version_counter.items())

    labels = [x[0] for x in items]
    values = [x[1] for x in items]
    values_v = [0 or vulnerable_counter[x] for x in labels]

    # Plot the vulnerabilities
    figure, ax = plt.subplots(1, 1, figsize=(6, 4))
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
    r1 = ax.bar(x - width / 2, values, width, label="Domains", color="w", edgecolor="k")
    r2 = ax.bar(x + width / 2, values_v, width, label="Vulnerable", color="#dddddd", edgecolor="k", hatch="//")

    # Add labels on the axis and the legend
    ax.set_ylabel("Number of domains")
    ax.set_xlabel("Facebook Graph API major version")
    ax.legend()

    figure.tight_layout()
    figure.savefig("figures/api_version.png", format="png")
    figure.savefig("figures/api_version.eps", format="eps")
    plt.show()


# Print the incomplete attacks
def print_incomplete_attacks(attack):
    domains = db.get_attack_incomplete(attack)
    for domain in domains:
        print(domain)
    print(f"Attack {attack} not complete for {len(domains)} domains")


# Print the table data in the format X (Y%)
def print_data(count, total, precision=1):
    percentage = "{0:.{p}f}".format(count*100/total, p=precision)
    return f"{count} ({percentage}%)"


def clean_attacks():
    attack_domains = db.get_attack_domains(state=None)
    print(len(attack_domains))
    attack_domain_names = [x["domain"] for x in attack_domains]
    for domain in db.all():
        facebook = get_facebook(domain)
        if domain["domain"] not in attack_domain_names:
            vulnerable = [f"vulnerable_{x}" for x in get_all_attacks()]
            for _property in vulnerable + ["authorization_response", "state", "new_state"]:
                if _property in facebook:
                    del facebook[_property]
                    db.update(domain, doc_ids=[domain.doc_id])


# Plot the vulenable domains in the different configurations
def plot_vulnerable_configurations(attacks="0,1,2,3"):
    # Get the vulnerabilities
    domains = FacebookDomains().get_attack_domains()
    attack_ids = attacks.split(",")
    values, values_v = [], []

    labels = [f"Attack {x}" for x in attack_ids]

    for attack in attack_ids:
        values.append(len(get_vulnerable(domains, attack)))
        values_v.append(len(get_vulnerable(domains, f"{attack}v")))

    # Plot the vulnerabilities
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
    r1 = ax.bar(x - width / 2, values, width, label="Base configuration", color="w", edgecolor="k")
    r2 = ax.bar(x + width / 2, values_v, width, label="Alternative configuration", color="#dddddd", edgecolor="k", hatch="//")

    # Add labels on the axis and the legend
    ax.set_ylabel("Vulnerable domains")
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
    figure.savefig("figures/vulnerable_configurations.png", format="png")
    figure.savefig("figures/vulnerable_configurations.eps", format="eps")
    plt.show()


# Get the display property for Facebook logins
def get_display_mode(domains):
    display_mode, popup_domains = [], []
    for domain in domains:
        facebook = get_facebook(domain)
        url = get_facebook_base_url(facebook.get("authorization_url"))
        if url:
            display = get_parameter(url, "display")
            display_mode.append(display)
            if display == "popup":
                popup_domains.append(domain)
    counter = Counter(display_mode)
    print(counter.most_common())
    for domain in popup_domains:
        print(domain["domain"])

    vulnerable = get_vulnerable(popup_domains, attacks=get_all_attacks())
    for domain in vulnerable:
        print(domain)
    analyze_vulnerabilities(domains=popup_domains)


# Plot the excluded domains
def analyse_exclusions():
    all_domains = db.all()
    registration_errors = len(db.get_registration_errors())
    no_code_flow = len(db.get_no_code_flow())
    authorization_errors = len(db.get_authorization_errors())
    login_errors = len(db.get_login_incomplete())
    attack_domains = len(db.get_attack_domains())

    labels = [f"Registration errors ({registration_errors})",
              f"No code flow ({no_code_flow})",
              f"Authorization errors ({authorization_errors})",
              f"Login errors ({login_errors})",
              f"Valid websites ({attack_domains})"]
    sizes = [registration_errors, no_code_flow, authorization_errors, login_errors, attack_domains]
    colors = ['#ff7675', '#fab1a0', '#ffeaa7', '#fdcb6e', "#74b9ff"]

    figure, texts, autotext = plt.pie(sizes, autopct="%1.1f%%", colors=colors, startangle=213)
    plt.legend(figure, labels, loc="center left", bbox_to_anchor=(0.7, 0.75), prop={'size': 10}, framealpha=1)
    # plt.setp(autot, size=12, weight=200)
    plt.savefig("figures/exclusions.png", format="png", bbox_inches="tight")
    plt.savefig("figures/exclusions.eps", format="eps", bbox_inches="tight")
    plt.show()


# Get the property values for the given domains
def get_property_values(domains, _property):
    values = []
    for domain in domains:
        facebook = get_facebook(domain)
        values.append(facebook.get(_property) if _property in facebook else None)
    return Counter(values).most_common()


# Analyze the property values of the given domains
def analyze_property_values(domains):
    properties = ["registration_error", "oauth_flow", "marker", "authorization_error", "authorization_response"]
    for _property in properties:
        values = get_property_values(domains, _property)
        print(f"{_property}: {values}")


def get_correct():
    database = FacebookDomains("facebook")
    all_domains = database.get_all()
    incomplete = database.get_incomplete()
    login_domains = database.get_login_domains()
    login_incomplete = database.get_login_incomplete()
    attack_domains = database.get_attack_domains()
    attack_incomplete = database.get_attack_incomplete()
    attack2_domains = database.get_attack_domains_with_state()
    attack2_incomplete = database.get_attack2_incomplete()
    attack3_incomplete = database.get_attack3_incomplete()

    print(f"all: {len(all_domains)}")
    print(f"incomplete: {len(incomplete)}")
    for domain in incomplete:
        print(domain)
    print(f"login_domains: {len(login_domains)}")
    print(f"login_incomplete: {len(login_incomplete)}")
    for domain in login_incomplete:
        print(domain)
    print(f"attack_domains: {len(attack_domains)}")
    print(f"attack2_domains: {len(attack2_domains)}")
    for domain in attack2_domains:
        print(domain)
    print(f"attack_incomplete: {len(attack_incomplete)}")
    for domain in attack_incomplete:
        print(domain)
    print(f"attack2_incomplete: {len(attack2_incomplete)}")
    for domain in attack2_incomplete:
        print(domain)
    print(f"attack3_incomplete: {len(attack3_incomplete)}")
    for domain in attack3_incomplete:
        print(domain)


# Analyze the vulnerable domains
def analyze_vulnerabilities(domains=None, attacks=None, none_is_false=False):
    attacks = attacks or get_all_attacks()
    domains = domains or db.get_attack_domains(state=None)
    vulnerable = defaultdict(int)
    not_vulnerable = 0

    results = []
    for domain in domains:
        facebook = get_facebook(domain)
        vulnerabilities = []
        for attack in attacks:
            vulnerability = facebook.get(f"vulnerable_{attack}")
            if not vulnerability and none_is_false:
                vulnerability = False
            vulnerabilities.append(vulnerability)
            if vulnerability:
                vulnerable[attack] += 1
        results.append(json.dumps(vulnerabilities))
        not_vulnerable += 1 if not any(vulnerabilities) else 0

    counter = Counter(results)
    total = sum(counter.values())

    table = [attacks + ["Domains"]]
    for item in counter.most_common():
        data = [x for x in json.loads(item[0])]
        data.append(print_data(item[1], total))
        table.append(data)
    print(tabulate(table, headers="firstrow", tablefmt="latex"))

    print(f"\nTotal domains: {total}")
    print(f"Vulnerable domains: {total - not_vulnerable}")
    print(vulnerable)


# Analyze the vulnerable domains
def analyze_combined_vulnerabilities(domains, attack):
    database = FacebookDomains()
    vulnerable = defaultdict(int)

    for domain in domains:
        facebook = database.get_facebook_info(domain)
        a = bool(facebook.get(f"vulnerable_{attack}"))
        b = bool(facebook.get(f"vulnerable_{attack}v"))
        vulnerable["a"] += 1 if a else 0
        vulnerable["b"] += 1 if b else 0
        vulnerable["or"] += 1 if a or b else 0
        vulnerable["and"] += 1 if a and b else 0

    total = len(domains)
    data = []
    table = [[f"{attack}A", f"{attack}B", f"{attack}A or {attack}B", f"{attack}A and {attack}B"]]
    for item in ["a", "b", "or", "and"]:
        data.append(print_data(vulnerable[item], total))
    table.append(data)
    print(tabulate(table, headers="firstrow", tablefmt="latex"))
    print(f"\nTotal domains: {total}")


# Analyze the domains using a constant state
def analyze_constant_state(domains):
    constant = []
    for domain in domains:
        facebook = get_facebook(domain)
        # Extract the states used by the domain
        url = get_facebook_base_url(facebook.get("authorization_url"))
        state = get_parameter(url, "state")
        attack_state = facebook.get("state")
        if state == attack_state:
            constant.append(domain)
        # print(f"\n{domain['domain']}\n{state}\n{attack_state}")

    for domain in constant:
        print(domain)
    print(f"Domains with constant state: {len(constant)}\n")
    analyze_vulnerabilities(domains=constant, attacks=["1v", "2v", "3v"])


def analyze_state_presence(domains):
    present = db.get_attack_domains(state=True)
    absent = db.get_attack_domains(state=False)
    table = [["State", "Domains", "Vulnerable"]]
    table.append(["Present", print_data(len(present), len(domains)), print_data(len(get_vulnerable(present)), len(present))])
    table.append(["Absent", print_data(len(absent), len(domains)), print_data(len(get_vulnerable(absent)), len(absent))])
    table.append(["Total", len(domains), print_data(len(get_vulnerable(domains)), len(domains))])
    print(tabulate(table, headers="firstrow", tablefmt="latex"))


def analyse_domains():
    all_domains = db.all()
    registration_errors = db.get_registration_errors()
    auth_errors = db.get_authorization_errors()
    login_incomplete = db.get_login_incomplete()
    no_code_flow = db.get_no_code_flow()
    #domains = db.get_all()
    incomplete = db.get_incomplete()
    login_domains = db.get_login_domains()
    attack_domains = db.get_attack_domains()
    attack_domains_state = db.get_attack_domains(state=True)
    attack_domains_no_state = db.get_attack_domains(state=False)

    print(f"All domains: {len(all_domains)}")
    print(f"Registration errors: {len(registration_errors)}")
    print(f"No code flow: {len(no_code_flow)}")
    print(f"Authorization errors: {len(auth_errors)}")
    print(f"Login incomplete: {len(login_incomplete)}")
    print(f"Attack domains: {len(attack_domains)}")
    # print(f"All Facebook domains without register errors: {len(domains)}")
    print(f"Incomplete: {len(incomplete)}")
    print(f"Login domains: {len(login_domains)}")
    print(f"Attack domains with state: {len(attack_domains_state)}")
    print(f"Attack domains without state: {len(attack_domains_no_state)}")

    for attack in "1,1v".split(","):
        result = db.get_attack_incomplete(attack, with_state=False)
        print(f"Attack {attack} incomplete: {len(result)}")

    for attack in "2,3,2v,3v".split(","):
        result = db.get_attack_incomplete(attack, with_state=True)
        print(f"Attack {attack} incomplete: {len(result)}")

    '''for domain in auth_errors:
        facebook = db.get_facebook_info(domain)
        error = facebook.get("authorization_error")
        print(error)'''

    labels = ['Authorization errors', 'OAuth flow', 'Registration errors', 'Login errors', "Valid websites"]
    sizes = [len(auth_errors), len(no_code_flow), len(registration_errors), len(login_incomplete), len(attack_domains)]
    colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', "silver"]
    explode = (0, 0, 0, 0, 0.1)  # explode 1st slice

    patches, texts = plt.pie(sizes, colors=colors, shadow=True, startangle=90)
    plt.legend(patches, labels, loc="best")
    plt.axis('equal')
    plt.tight_layout()
    plt.show()


def get_missing_login():
    results = defaultdict(int)
    domains = db.get_attack_domains()
    for domain in domains:
        facebook = get_facebook(domain)

        if "victim_marker" not in facebook:
            results["missing_victim"] += 1
            print(domain)
        elif not facebook.get("victim_marker"):
            results["fail_victim"] += 1
        else:
            results["ok_victim"] += 1

        if "attacker_marker" not in facebook:
            results["missing_attacker"] += 1
            print(domain)
        elif not facebook.get("attacker_marker"):
            results["fail_attacker"] += 1
            print(domain["domain"])
        else:
            results["ok_attacker"] += 1
    print(results)


def main():
    print("Analysis")
    # domains = db.get_login_domains()
    # print(len(domains))
    # analyze_vulnerabilities(domains, attacks=["1a","1b","1c"])
    # get_missing_login()
    # get_api_versions()
    # analyze_vulnerabilities(attack_string="0,0v")
    # add_registration_errors()
    # analyze_all()
    # get_correct()
    # get_missing()
    # get_applications()
    # get_api_versions()
    # plot_vulnerable_configurations()
    # get_display_mode()
    # clean_attacks()
    # analyse_domains()
    # analyse_exclusions()
    # analyze_constant_state()
    # analyze_state_presence()
    # print_incomplete()
    # get_logins()
    # get_vulnerables()
    # print_state_lengths()
    # get_states()


if __name__ == "__main__":
    main()
