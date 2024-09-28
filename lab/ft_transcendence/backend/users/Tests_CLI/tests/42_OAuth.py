import webbrowser, os

CLIENT_ID = os.environ.get('UID_INTRA')
AUTH_URL = 'https://api.intra.42.fr/oauth/authorize'
REDIRECT_URI = 'http://localhost:8000/api/complete/intra42/'

def main():
    auth_url = f"{AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    print("Opening the browser with the url:")
    print("="*100)
    print(auth_url)
    print("="*100)
    webbrowser.open(auth_url)
    print("Please login to your 42 account and authorize the app.")
    print("After that, you will be redirected to a page with the user information.")

if __name__ == "__main__":
    main()
