from selenium.webdriver.firefox.options import Options as FirefoxOptions
from seleniumwire.webdriver import Firefox, FirefoxProfile
from webdriver.firefox_preferences import preferences
from os import path, name
import traceback
import sys
import pickle
from pathlib import Path
import json


directory = path.dirname(__file__)
system = "win" if name == "nt" else "linux"
firefox_path = path.join(directory, f"webdriver/geckodriver-v0.26.0-{system}64/geckodriver")
extension_path = path.join(directory, "extensions/redirect-blocker/redirect-blocker.xpi")


class Driver(Firefox):

    def __init__(self, headless=True):
        try:
            options = FirefoxOptions()
            options.headless = headless
            profile = FirefoxProfile()
            self._set_firefox_preferences(profile)
            self.main_window = None
            seleniumwire_options = {
                "mitmproxy_log_level": "ERROR",
                "backend": "mitmproxy",
                "request_storage_base_dir": directory
            }

            Firefox.__init__(self, executable_path=firefox_path, options=options,
                             firefox_profile=profile,seleniumwire_options=seleniumwire_options)

            self.set_page_load_timeout(60)

        except:
            print("ERROR Running the browser")
            print(traceback.format_exc(), file=sys.stderr)

    # Install the browser extension to block the OAuth flow
    def install_extension(self):
        _path = extension_path.replace('/', '\\') if system == "win" else extension_path
        # TODO: Sign the extension and remove temporary=True
        self.install_addon(_path, temporary=True)

    @staticmethod
    def _set_firefox_preferences(profile):
        # Set the Firefox profile
        for key, value in preferences.items():
            profile.set_preference(key, value)

    # Create the folder and return the file path
    @staticmethod
    def get_data_path(folder, domain_name):
        Path(f"results/data/{folder}").mkdir(parents=True, exist_ok=True)
        return f"results/data/{folder}/{domain_name}"

    # Save the cookies set by the website
    def save_cookies(self, folder, domain):
        full_path = self.get_data_path(folder, domain["domain"])
        with open(f"{full_path}.json", "w", encoding="utf-8") as file:
            json.dump(self.get_cookies(), file, indent=4)

    # Save the login cookies set by the website
    def save_login_cookies(self, filename):
        with open(f"webdriver/{filename}", "wb") as file:
            pickle.dump(self.get_cookies(), file)

    # Load the previously saved login cookies
    def load_login_cookies(self, filename):
        with open(f"webdriver/{filename}", "rb") as file:
            cookies = pickle.load(file)
            #cookies['expiry'] = cookies.get('expiry', -1)
            for cookie in cookies:
                self.add_cookie(cookie)

    # Save the source of the page in a file
    def save_source(self, full_path):
        with open(f"{full_path}.html", "w", encoding="utf-8") as file:
            file.write(self.page_source)

    # Save a screenshot for the domain
    def screenshot(self, full_path):
        self.save_screenshot(f"{full_path}.png")

    # Save the page source and a screenshot
    def save_data(self, folder, domain):
        full_path = self.get_data_path(folder, domain["domain"])
        self.save_source(full_path)
        self.screenshot(full_path)

    # Save the network traffic
    def save_requests(self, folder, domain_name):
        full_path = self.get_data_path(folder, domain_name)
        with open(f"{full_path}.json", "w", encoding="utf-8") as file:
            json.dump(self.get_requests(), file, indent=4)

    # Get the element containing the given class
    def contains_class(self, class_name):
        elements = self.find_elements_by_xpath("//*")
        for element in elements:
            classes = element.get_attribute("class")
            if classes and class_name in classes:
                return element

    # Get the requests saved by the proxy
    def get_requests(self):
        requests = []
        for request in self.requests:
            try:
                data = {
                    "method": request.method,
                    "url": request.url,
                    "headers": json.loads(json.dumps(dict(request.headers))),
                    "response": None
                    # "body": request.body,
                }
                if request.response:
                    data["response"] = {
                        "status_code": request.response.status_code,
                        "headers": json.loads(json.dumps(dict(request.response.headers))),
                        # "body": request.response.body
                    }
                requests.append(data)
            except Exception as e:
                print(e)
        return requests
