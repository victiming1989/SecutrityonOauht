# import TimeUnit as TimeUnit
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, NoSuchWindowException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from utility.facebook import get_facebook, get_facebook_login
from utility.google import get_google, get_google_login
from utility.locators import FacebookLocators, GoogleLocators
from utility.data import Data, FacebookData, GoogleData
import random
import logging
import time
import json


class Provider:
    def __init__(self, driver):
        self.driver = driver
        self.long_wait = WebDriverWait(self.driver, Data.LONG_TIME)
        self.wait = WebDriverWait(self.driver, Data.MEDIUM_TIME)
        self.short_wait = WebDriverWait(self.driver, Data.SHORT_TIME)
        logging.basicConfig(level=logging.INFO)

    # Click on the given element
    def click(self, locator):
        try:
            element = self.wait.until(ec.element_to_be_clickable(locator))
            element.click()
        except Exception as e:
            # Workaround to click the element if covered by another element
            element = self.short_wait.until(ec.presence_of_element_located(locator))
            self.driver.execute_script("arguments[0].click();", element)
            logging.info(e)

    # Click on the given elements
    def click_all(self, locator, delay=.0):
        elements = self.long_wait.until(ec.presence_of_all_elements_located(locator))
        for element in elements:
            time.sleep(random.uniform(0, delay))
            self.driver.execute_script("arguments[0].click();", element)

    # Get the secondary browser window
    def get_secondary_window(self):
        window = self.driver.current_window_handle
        return [x for x in self.driver.window_handles if x != window][0]

    # Switch from main to secondary window, if needed
    def switch_window(self):  # !! pop up window
        try:
            self.short_wait.until(ec.number_of_windows_to_be(2))
            # Keep track of the windows
            self.driver.main_window = self.driver.current_window_handle
            self.driver.switch_to.window(self.get_secondary_window())
            time.sleep(Data.SHORT_TIME)
        except TimeoutException:
            pass

    # Switch back to the main window
    def switch_back_window(self, forced=False):
        if self.driver.main_window:
            try:
                if not forced:
                    self.short_wait.until(ec.number_of_windows_to_be(1))
                self.driver.switch_to.window(self.driver.main_window)
                time.sleep(Data.SHORT_TIME)
            except TimeoutException:
                pass

    # Check if the element is present in page
    def is_present(self, locator):
        try:
            element = self.short_wait.until(ec.presence_of_element_located(locator))
            return bool(element)
        except TimeoutException:
            return False

    # Simulate a human behaviour in text insertion
    @staticmethod
    def human_send_keys(input_field, text):
        for character in text:
            time.sleep(random.random() / 5)
            input_field.send_keys(character)


class Facebook(Provider):
    def __init__(self, driver):
        super().__init__(driver)

    # Login in Facebook, using the form
    def login(self, username, password):
        # Reach the Facebook login page
        self.long_wait.until(ec.url_contains(FacebookData.LOGIN_PAGE))
        form = self.long_wait.until(ec.presence_of_element_located(FacebookLocators.LOGIN_FORM))

        # Insert email and password in the form
        email = form.find_element_by_id(FacebookLocators.EMAIL)
        self.human_send_keys(email, username)
        password_field = form.find_element_by_id(FacebookLocators.PASSWORD)
        self.human_send_keys(password_field, password)
        password_field.send_keys(Keys.ENTER)
        self.long_wait.until_not(ec.url_contains(FacebookData.LOGIN_PAGE))
        logging.info("Facebook login performed")

    # Do the login using the saved cookies
    def cookie_login(self, cookies):
        self.driver.get(FacebookData.BASE_URL)
        self.driver.load_login_cookies(cookies)
        logging.info("Facebook cookie login performed")

    # Reinsert the Facebook password to proceed
    def re_authorize(self, password):  # !!
        form = self.wait.until(ec.presence_of_element_located(FacebookLocators.RE_AUTH_FORM))
        password_field = form.find_element_by_name(FacebookLocators.PASSWORD)
        self.human_send_keys(password_field, password)
        password_field.send_keys(Keys.ENTER)
        time.sleep(Data.SHORT_TIME)

    # Perform Facebook authorization
    def authorize(self, password):  # !!
        try:
            # Complete the Facebook re-authorization request
            if FacebookData.RE_AUTH_PAGE in self.driver.current_url:
                self.re_authorize(password)

            # Reach the authorization form and check the presence of errors in the process
            form = self.short_wait.until(ec.presence_of_element_located(FacebookLocators.AUTH_FORM))
            errors = form.find_elements_by_xpath(FacebookLocators.AUTH_ERROR)
            if errors:
                return json.loads(errors[0].get_attribute("value")).get("error_message")

            # Submit the form
            form.submit()
        except (TimeoutException, NoSuchWindowException):
            pass

        # Switch back to the main window if needed
        self.switch_back_window()
        logging.info("Facebook authorization performed")

    # Go to the Facebook login page
    def reach_login(self, domain):  # !!
        # Get the facebook information for the domain
        facebook = get_facebook(domain)

        if facebook["internal"]:
            # Follow the internal redirect page
            self.driver.get(facebook["internal"])

        elif facebook["button"]:
            # A button click is needed to reach the login page
            self.driver.get(domain["login"])
            self.click((By.XPATH, facebook["button"]))
            self.switch_window()
        else:
            # An IdP direct link must be found in page
            self.driver.get(domain["login"])
            login_page = get_facebook_login(self.driver.page_source)
            self.driver.get(login_page)

    # Remove the authorization to the Facebook applications
    def remove_applications(self):
        # Go to the settings page with the list of applications
        self.driver.get(FacebookData.APPLICATIONS_PAGE)

        if self.is_present(FacebookLocators.DELETE_CHECKS):
            if self.is_present(FacebookLocators.SEE_MORE_BUTTON):
                # Click on 'See More' and show all the applications
                self.click(FacebookLocators.SEE_MORE_BUTTON)

            # Select the applications clicking the checkboxes
            self.click_all(FacebookLocators.DELETE_CHECKS, delay=0.3)

            # Submit and confirm the removal of the applications
            self.driver.find_element_by_xpath(FacebookLocators.DELETE_FORM).submit()
            self.click(FacebookLocators.DELETE_CONFIRM)
            time.sleep(Data.LONG_TIME)
            logging.info("Facebook applications removed")

    # Save the cookies set by Facebook after the login
    def save_login_cookies(self, cookies, username, password):
        # Perform the Facebook login
        self.driver.get(FacebookData.LOGIN_PAGE)
        self.login(username, password)
        # Save the login cookies
        self.driver.save_login_cookies(cookies)

    # Extract the authorization response from the page
    def get_authorization_response(self):
        try:
            self.long_wait.until(ec.url_contains("data:"))
            return self.driver.find_element_by_tag_name("pre").text
        except TimeoutException:
            pass

    # Go to the internal page with the marker
    def reach_marker_page(self, domain):
        try:
            self.wait.until_not(ec.url_contains(FacebookData.BASE_URL))
            marker_url = get_facebook(domain).get("marker_url")
            if marker_url:
                logging.info("Go to the internal page with the marker")
                self.driver.get(marker_url)
            time.sleep(Data.SHORT_TIME)
        except TimeoutException:
            return "Marker page not reached"


class Google(Provider):
    def __init__(self, driver):
        super().__init__(driver)

    # Login in Google, using the form
    def login(self, username, password):
        # Reach the Google login page
        self.long_wait.until(ec.url_contains(GoogleData.LOGIN_PAGE))
        form = self.long_wait.until(ec.presence_of_element_located(GoogleLocators.LOGIN_FORM))  # !!

        # Insert email and password in the form
        email = form.find_element_by_id(GoogleLocators.EMAIL)
        self.human_send_keys(email, username)
        email.send_keys(Keys.ENTER)
        time.sleep(5)
        # Thread.sleep(3000);
        # self.driver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS)
        # next_field= form.find_element_by_xpath(GoogleLocators.NextButton)
        # print("this is the next field  :  "+str(next_field))
        # next_field.click()
        # self.long_wait.until_not(ec.url_contains(GoogleData.LOGIN_PAGE))
        # self.long_wait.until(ec.presence_of_element_located(GoogleLocators.Next_AUTH))
        password_field = form.find_elements_by_name(GoogleLocators.PASSWORD)
        self.human_send_keys(password_field[0], password)
        # (password_field).send_keys(Keys.ENTER)
        fin_button = form.find_element_by_xpath(GoogleLocators.AUTH_BUTTON)
        fin_button.click()
        self.long_wait.until_not(ec.url_contains(GoogleData.LOGIN_PAGE))
        logging.info("Google login performed")

    # Do the login using the saved cookies
    def cookie_login(self, cookies):
        self.driver.get(GoogleData.BASE_URL)
        self.driver.load_login_cookies(cookies)
        logging.info("Google cookie login performed")

    # Reinsert the Google password to proceed
    def re_authorize(self, password):  # !!
        form = self.wait.until(ec.presence_of_element_located(GoogleLocators.RE_AUTH_FORM))
        password_field = form.find_element_by_id(GoogleLocators.PASSWORD)
        self.human_send_keys(password_field, password)
        password_field.send_keys(Keys.ENTER)
        time.sleep(Data.SHORT_TIME)

    # Perform Google authorization
    def authorize(self, password):  # !!
        try:
            # Complete the Facebook re-authorization request
            if GoogleData.RE_AUTH_PAGE in self.driver.current_url:
                self.re_authorize(password)

            # Reach the authorization form and check the presence of errors in the process
            form = self.short_wait.until(ec.presence_of_element_located(GoogleLocators.AUTH_FORM))
            errors = form.find_elements_by_xpath(GoogleLocators.AUTH_ERROR)
            errors2 = form.find_elements_by_xpath(GoogleLocators.AUTH_ERROR_BUTTON)
            if errors:
                return json.loads(errors[0].get_attribute("value")).get("error_message")
            if errors2:
                return json.loads(errors2[0].get_attribute("value")).get("error_message")

            # Submit the form
            form.submit()
        except (TimeoutException, NoSuchWindowException):
            pass

        # Switch back to the main window if needed
        self.switch_back_window()
        logging.info("Google authorization performed")

    # Go to the Google login page
    def reach_login(self, domain):  # !!
        # Get the Google information for the domain

        google = get_google(domain)

        if google["internal"]:
            # Follow the internal redirect page
            self.driver.get(google["internal"])

        elif google["button"]:
            # A button click is needed to reach the login page
            self.driver.get(domain["login"])
            self.click((By.XPATH, google["button"]))
            self.switch_window()
        else:
            # An IdP direct link must be found in page
            self.driver.get(domain["login"])
            login_page = get_google_login(self.driver.page_source)
            self.driver.get(login_page)

    # Save the cookies set by Google after the login
    def save_login_cookies(self, cookies, username, password):
        # Perform the Google login
        self.driver.get(GoogleData.LOGIN_PAGE)
        self.login(username, password)
        # Save the login cookies
        self.driver.save_login_cookies(cookies)

    # Extract the authorization response from the page
    def get_authorization_response(self):
        try:
            self.long_wait.until(ec.url_contains("data:"))
            return self.driver.find_element_by_tag_name("pre").text
        except TimeoutException:
            pass

    # Go to the internal page with the marker
    def reach_marker_page(self, domain):
        try:
            self.wait.until_not(ec.url_contains(GoogleData.BASE_URL))
            marker_url = get_google(domain).get("marker_url")
            if marker_url:
                logging.info("Go to the internal page with the marker")
                self.driver.get(marker_url)
            time.sleep(Data.MEDIUM_TIME)
        except TimeoutException:
            return "Marker page not reached"
