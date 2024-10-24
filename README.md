# User Management System
- This project is a User Management System built with `Django` and designed to be run using `Docker Compose`.
- The system provides key features like user authentication, profile management, GDPR compliance, and more. It is containerized for ease of deployment, with a Makefile to automate Docker commands.

# [API Documentation](https://github.com/AhmedFatir/user-management-system/backend/API.md)

## Main Features
### 1. Authentication
- Register: Allows users to register with their username, email, and password.
- Login: Authenticates users and returns access and refresh tokens.
- Logout: Logs out users by invalidating their refresh tokens.
- Delete Account: Allows logged-in users to delete their account.
### 2. Users Management
- View a list of all users (admin only).
- Retrieve, update, or delete specific users.
### 3. Password Management
- Change Password: Allows users to change their password.
- Reset Password: Sends password reset emails and allows resetting passwords using a token.
### 4. 2FA Management
- Manage two-factor authentication (2FA) for additional security.
### 5. Intra42 Login
- Integrates with the 42 Intra API for login functionality.
### 6. Profile Management
- Users can view and update their profiles.
### 7. Friends Management
- Allows users to add or remove friends and view friend lists.
### 8. GDPR Compliance
- Provides features to comply with GDPR regulations, including user data access and deletion requests.


## Technologies
- **Backend**: Django, Django REST framework
- **Database**: SQLite
- **Authentication**: JWT, OAuth2
- **Containerization**: Docker, Docker Compose
- **Testing**: pytest, postman, CLI-based testing

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
## if you are a 42 student and want to run this project on the school's Mac, you may need to change the path where Docker Desktop on Mac stores its data.
```bash
# Make sure Docker Desktop is not running.

# Use the rsync command to copy the Docker data directory to the new location.
rsync -a ~/Library/Containers/com.docker.docker ~/goinfre/DockerData

# Create a symbolic link from the new location back to the original location.
ln -s ~/goinfre/DockerData/com.docker.docker ~/Library/Containers/com.docker.docker

# Open Docker > Preferences > Resources > File Sharing > Add ~/goinfre to Shared Paths.
```