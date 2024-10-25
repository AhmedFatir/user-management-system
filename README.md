# User Management System
- This project is a User Management System built with `Django` and designed to be run using `Docker Compose`.

## Technologies
- **Backend**: [Django](https://www.djangoproject.com/), [Django REST framework](https://www.django-rest-framework.org/)
- **Database**: [SQLite](https://www.sqlite.org/index.html)
- **Authentication**: [JWT](https://jwt.io/), [OAuth2](https://oauth.net/2/)
- **Containerization**: [Docker](https://www.docker.com/), [Docker Compose](https://docs.docker.com/compose/)
- **Testing**: [Unittest](https://docs.python.org/3/library/unittest.html#module-unittest), [Postman](https://www.postman.com/), [CLI-based Testing](https://github.com/AhmedFatir/user-management-system/tree/master/CLI-Tests)

# [API Documentation](https://github.com/AhmedFatir/user-management-system/blob/master/backend/API.md)

## Main Features
### 1. Authentication with JWT (JSON Web Tokens)
- Register: Allows users to register with their username, email, and password.
- Login: Authenticates users and returns access and refresh tokens.
- Logout: Logs out users by invalidating their refresh tokens.
- Delete Account: Allows logged-in users to delete their account.
- Refresh Token: Allows users to refresh their access token using a refresh token.
### 2. Users Management
- View a list of all users.
- Retrieve a specific user.
- Retrieve the currently logged-in user.
### 3. Password Management
- Change Password: Allows users to change their password.
- Reset Password: Sends password reset emails and allows resetting passwords using a token.
### 4. 2FA Management
- Manage two-factor authentication (2FA) for additional security.
### 5. Intra42 Login
- Integrates with the 42 Intra API for login functionality.
### 6. Profile Management
- Users can view and update their profile informations and profile picture.
### 7. Friends Management
- Allows users to add or remove friends and view friend lists.
- Users can also block or unblock other users.
### 8. GDPR Compliance
- Provides features to comply with [GDPR regulations](https://gdpr.eu/), including user data anonymization and deletion.

## Setup
### If you don't have docker and docker-compose on your machine
```bash
apt install curl

apt install docker.io

curl -O -J -L https://github.com/docker/compose/releases/download/v2.11.2/docker-compose-linux-x86_64

chmod +x docker-compose-linux-x86_64

cp ./docker-compose-linux-x86_64 /usr/bin/docker-compose && rm ./docker-compose-linux-x86_64
```
### If you already have docker and docker-compose installed on your machine
```bash
git clone https://github.com/AhmedFatir/user-management-system.git

cd user-management-system

make
```
## If you are a 42 student and want to run this project on the school's Mac, you may need to change the path where Docker Desktop on Mac stores its data.
```bash
# Make sure Docker Desktop is not running.

# Use the rsync command to copy the Docker data directory to the new location.
rsync -a ~/Library/Containers/com.docker.docker ~/goinfre/DockerData

# Create a symbolic link from the new location back to the original location.
ln -s ~/goinfre/DockerData/com.docker.docker ~/Library/Containers/com.docker.docker

# Open Docker > Preferences > Resources > File Sharing > Add ~/goinfre to Shared Paths.
```