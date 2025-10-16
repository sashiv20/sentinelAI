import requests
import json
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning for self-signed certificates (for demo/lab use only)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger("vmanage")
logger.addHandler(logging.FileHandler('test.log', 'a'))

class VManageSession:
    """
    Handles authenticated REST API sessions with Cisco vManage.
    """

    def __init__(self, vmanage_ip, username, password):
        """
        Initialize the session and log in to vManage.
        """
        self.vmanage_ip = vmanage_ip
        self.base_url = f'https://{vmanage_ip}'
        self.session = requests.Session()
        self.token = ''
        self.logged_in = False
        self.login(username, password)

    def login(self, username, password):
        """
        Authenticate with vManage and obtain a session + CSRF token.
        """
        login_url = f'{self.base_url}/j_security_check'
        login_data = {'j_username': username, 'j_password': password}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        try:
            resp = self.session.post(login_url, data=login_data, headers=headers, verify=False)
            if resp.status_code != 200 or "<html>" in resp.text:
                logger.error("Login failed! Check your credentials or vManage URL.")
                raise Exception("vManage login failed.")
            logger.info("Login successful.")
            self.token = self.get_token()
            self.logged_in = True
        except Exception as e:
            logger.error(f"Exception during login: {e}")
            self.logged_in = False
            raise

    def get_token(self):
        """
        Fetch the CSRF token from vManage.
        """
        url = f'{self.base_url}/dataservice/client/token'
        try:
            resp = self.session.get(url, verify=False)
            if resp.status_code == 200:
                token = resp.text.strip()
                logger.info("CSRF token fetched successfully.")
                return token
            else:
                logger.warning("CSRF token endpoint returned non-200 status.")
                return ''
        except Exception as e:
            logger.warning(f"Could not fetch CSRF token: {e}")
            return ''

    def get_headers(self, is_json=True):
        """
        Construct headers for API requests.
        """
        headers = {'Accept': 'application/json'}
        if is_json:
            headers['Content-Type'] = 'application/json'
        if self.token:
            headers['X-XSRF-TOKEN'] = self.token
        return headers

    def get_request(self, mount_point):
        """
        Send a GET request to the given mount point.
        """
        url = f'{self.base_url}/dataservice/{mount_point.lstrip("/")}'
        try:
            resp = self.session.get(url, headers=self.get_headers(), verify=False)
            resp.raise_for_status()
            logger.info(f"GET {url} -> {resp.status_code}")
            return resp.json()
        except Exception as e:
            logger.error(f"GET request failed ({url}): {e}")
            return None

    def post_request(self, mount_point, payload, is_json=True):
        """
        Send a POST request to the given mount point.
        """
        url = f'{self.base_url}/dataservice/{mount_point.lstrip("/")}'
        try:
            if is_json:
                data = json.dumps(payload)
            else:
                data = payload  # For multipart/form-data
            resp = self.session.post(url, data=data, headers=self.get_headers(is_json), verify=False)
            resp.raise_for_status()
            logger.info(f"POST {url} -> {resp.status_code}")
            return resp.json()
        except Exception as e:
            logger.error(f"POST request failed ({url}): {e}")
            return None

    def version(self):
        """
        Fetch and return the vManage version string.
        """
        data = self.get_request("client/about")
        if data and "data" in data and "version" in data["data"]:
            return data["data"]["version"].strip()
        logger.warning("Could not fetch version.")
        return None

# ----------------------------
# Example usage (uncomment for real use):

if __name__ == "__main__":
    VMANAGE_IP = "10.0.0.1"       # <-- Replace with actual IP
    USERNAME = "admin"            # <-- Replace with actual username
    PASSWORD = "password"         # <-- Replace with actual password

    try:
        vmanage = VManageSession(VMANAGE_IP, USERNAME, PASSWORD)
        version = vmanage.version()
        print("vManage version:", version)
        # Example: fetch all devices
        devices = vmanage.get_request("device")
        print(json.dumps(devices, indent=2))
    except Exception as e:
        print(f"Failed: {e}")
