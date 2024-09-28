import requests
from getpass import getpass

BASE_URL = "http://localhost:8000/api"
REGISTER_URL = f"{BASE_URL}/register/"
LOGIN_URL = f"{BASE_URL}/login/"
VERIFY_2FA_URL = f"{BASE_URL}/verify-2fa/"
ENABLE_2FA_URL = f"{BASE_URL}/enable-2fa/"
VERIFY_ENABLE_2FA_URL = f"{BASE_URL}/verify-enable-2fa/"
DISABLE_2FA_URL = f"{BASE_URL}/disable-2fa/"


class APITester:
    def __init__(self):
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
        self.user_id = None
        self.username = None
        self.password = None
        self.email = None
        self.is_2fa_enabled = False

    def register_user(self):
        print("Registering user...")
        response = self.session.post(REGISTER_URL, json={
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "password2": self.password
        })
        if response.status_code == 201:
            data = response.json()
            self.access_token = data['access']
            self.refresh_token = data['refresh']
            print("User registered successfully.")
        else:
            print(f"Registration failed. Status code: {response.status_code}")
            print(response.text)

    def login(self):
        print("Logging in...")
        response = self.session.post(LOGIN_URL, json={
            "username": self.username,
            "password": self.password
        })
        if response.status_code == 200:
            data = response.json()
            if 'user_id' in data:  # 2FA is required
                self.user_id = data['user_id']
                self.is_2fa_enabled = True
                print("2FA is enabled. Check your email for the code.")
                code = input("Enter the 2FA code: ")
                self.verify_2fa(code)
            else:
                self.access_token = data['access']
                self.refresh_token = data['refresh']
                self.is_2fa_enabled = False
                print("Logged in successfully.")
        else:
            print(f"Login failed. Status code: {response.status_code}")
            print(response.text)

    def enable_2fa(self):
        print("Enabling 2FA...")
        response = self.session.post(ENABLE_2FA_URL, headers={
            "Authorization": f"Bearer {self.access_token}"
        })
        if response.status_code == 200:
            print("2FA enablement initiated. Check your email for the code.")
            code = input("Enter the 2FA enablement code: ")
            self.verify_enable_2fa(code)
        else:
            print(f"2FA enablement failed. Status code: {response.status_code}")
            print(response.text)

    def verify_enable_2fa(self, code):
        response = self.session.post(VERIFY_ENABLE_2FA_URL, headers={
            "Authorization": f"Bearer {self.access_token}"
        }, json={"code": code})
        if response.status_code == 200:
            print("2FA enabled successfully.")
            self.is_2fa_enabled = True
        else:
            print(f"2FA verification failed. Status code: {response.status_code}")
            print(response.text)

    def verify_2fa(self, code):
        print("Verifying 2FA...")
        response = self.session.post(VERIFY_2FA_URL, json={
            "user_id": self.user_id,
            "code": code
        })
        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access']
            self.refresh_token = data['refresh']
            print("2FA verified successfully.")
        else:
            print(f"2FA verification failed. Status code: {response.status_code}")
            print(response.text)

    def disable_2fa(self):
        print("Disabling 2FA...")
        response = self.session.post(DISABLE_2FA_URL, headers={
            "Authorization": f"Bearer {self.access_token}"
        })
        if response.status_code == 200:
            print("2FA disabled successfully.")
            self.is_2fa_enabled = False
        else:
            print(f"2FA disabling failed. Status code: {response.status_code}")
            print(response.text)

def main():
    tester = APITester()

    print("Welcome to the 2FA Email Test Suite")
    
    # Get user credentials
    tester.username = input("Enter your username: ")
    tester.password = getpass("Enter your password: ")
    tester.email = input("Enter your email: ")

    # Try to login
    tester.login()

    if not tester.access_token:
        # If login failed, try to register
        register = input("User not found. Would you like to register? (y/n): ")
        if register.lower() == 'y':
            tester.register_user()
            tester.login()
        else:
            print("Exiting...")
            return

    while True:
        print("\n" + "="*30)
        print(f"2FA is currently {'enabled' if tester.is_2fa_enabled else 'disabled'}.")
        print("="*30)
        print("Choose an option:")
        print("1. Enable 2FA")
        print("2. Disable 2FA")
        print("3. Test Login")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")
        print("="*30 + "\n")

        if choice == '1':
            if not tester.is_2fa_enabled:
                tester.enable_2fa()
            else:
                print("2FA is already enabled.")
        elif choice == '2':
            if tester.is_2fa_enabled:
                tester.disable_2fa()
            else:
                print("2FA is already disabled.")
        elif choice == '3':
            tester.login()
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

    print("Test suite completed.")

if __name__ == "__main__":
    main()