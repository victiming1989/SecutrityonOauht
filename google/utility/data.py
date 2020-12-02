
class Data:
    SHORT_TIME = 10
    MEDIUM_TIME = 20
    LONG_TIME = 50


class FacebookData:
    BASE_URL = "https://www.facebook.com"
    LOGIN_PAGE = f"{BASE_URL}/login.php"
    RE_AUTH_PAGE = f"{BASE_URL}/login/reauth.php"
    APPLICATIONS_PAGE = f"{BASE_URL}/settings?tab=applications"

class GoogleData:
    BASE_URL = "https://accounts.google.com/"
    LOGIN_PAGE = "https://accounts.google.com/"
    RE_AUTH_PAGE = f"{BASE_URL}signin/v2/challenge/pwd?passive"  #f"{BASE_URL}/login/reauth.php" #!!
    #APPLICATIONS_PAGE = f"{BASE_URL}/settings?tab=applications" #!!


class User:
    def __init__(self, name, username, password, markers, cookies):
        self.name = name
        self.username = username
        self.password = password
        self.markers = markers
        self.cookies = cookies


Attacker = User(
    "attacker",
    "deracoovampiri@gmail.com",
    "victoria2020UNI!",
    ["deracoo vampiri", "deracoovampiri", "deracoo", "vampiri","vampiri deracoo", "decaroo"],
    "google_cookies"
)
'''

Attacker = User(
    "attacker",
    "rossilauraa@yandex.com",
    "Security2020!",
    ["laura rossi", "rossi laura", "rossilaura"],
    "facebook_cookies"
)
'''
Victim = User(
    "victim",
    "victiming1989@gmail.com",
    "victoria2020UNI!",
    ["victoria", "timing", "victiming1989", "victiming", "victoria timing"],
    "google_victim_cookies"
)
