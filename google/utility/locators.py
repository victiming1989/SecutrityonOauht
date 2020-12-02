from selenium.webdriver.common.by import By


class FacebookLocators:
    # Login page locators
    LOGIN_FORM = (By.ID, "login_form")
    EMAIL = "email"
    PASSWORD = "pass"
    # Authorization page locators
    AUTH_FORM = (By.ID, "platformDialogForm")
    AUTH_BUTTON = (By.XPATH, "//button[@type='submit']")
    RE_AUTH_FORM = (By.XPATH, "//form[contains(@action, 'login/reauth.php')]")
    AUTH_ERROR = "//input[@name='error']"
    # Applications page locators
    SEE_MORE_BUTTON = (By.XPATH, "//span[contains(text(), 'See More')]")
    DELETE_FORM = "//form[@ajaxify='/ajax/settings/apps/delete_app_multi/']"
    DELETE_CONFIRM = (By.XPATH, "//button[@name='confirmed']")
    DELETE_CHECKS = (By.XPATH, "//button[@aria-label='Select Row']")

class GoogleLocators:
    # Login page locators
    LOGIN_FORM = (By.ID, "view_container")  # (By.XPATH, "//*[@id='view_container']")  #(By.ID, "login_form")
    EMAIL = "identifierId"  # (By.XPATH, "//*[@id='identifierId']")
    PASSWORD = "password"
    NextButton = "//*[@id='identifierNext']/div/button"
    # Authorization page locators
    AUTH_FORM = (By.ID, "view_container")
    RE_AUTH_FORM = (By.ID, "passwordNext")
    Next_AUTH = (By.ID, "passwordNext")

    AUTH_BUTTON = "//*[@id='passwordNext']/div/button"  # "//*[@id='passwordNext']/div/button"
    AUTH_ERROR = "//*[@id='af-error-container']"
    AUTH_ERROR_BUTTON = "//*[@id='next']/div/button"

