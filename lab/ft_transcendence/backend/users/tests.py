from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage

from django.test import override_settings
from django.conf import settings
import os, time, io, tempfile, shutil
from django.utils import timezone
from PIL import Image

from users.models import TwoFactorCode
User = get_user_model()


class RegistrationTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.register_url = reverse('register')
		self.user_data = {
			'username': 'testuser',
			'email': 'testuser@example.com',
			'password': 'testpass123',
			'password2': 'testpass123'
		}

	def test_registration(self):
		response = self.client.post(self.register_url, self.user_data)
		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertIn('refresh', response.data)
		self.assertIn('access', response.data)
		self.assertIn('user', response.data)
		self.assertEqual(User.objects.count(), 1)
		self.assertEqual(User.objects.get().username, 'testuser')

	def test_registration_with_invalid_data(self):
		invalid_data = self.user_data.copy()
		invalid_data['password2'] = 'wrongpassword'
		response = self.client.post(self.register_url, invalid_data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertEqual(User.objects.count(), 0)
	
	def test_registration_with_existing_email(self):
		User.objects.create_user(username='existinguser', email='testuser@example.com', password='testpass123')

		new_user_data = self.user_data.copy()
		new_user_data['username'] = 'newuser'
		response = self.client.post(self.register_url, new_user_data)
		
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('email', response.data)
		self.assertIn('already exists', str(response.data['email']).lower())
		self.assertEqual(User.objects.count(), 1)  # Ensure no new user was created

	def test_registration_with_existing_username(self):
		User.objects.create_user(username='testuser', email='existinguser@example.com', password='testpass123')

		new_user_data = self.user_data.copy()
		new_user_data['email'] = 'newuser@example.com'
		response = self.client.post(self.register_url, new_user_data)
		
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('username', response.data)
		self.assertIn('already exists', str(response.data['username']).lower())
		self.assertEqual(User.objects.count(), 1)  # Ensure no new user was created

class LoginTestCase(TestCase):

	def setUp(self):
		self.client = APIClient()
		self.login_url = reverse('login')

	def test_user_login(self):
		User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		
		# Then, attempt to log in
		login_data = {
			'username': 'testuser',
			'password': 'testpass123'
		}
		response = self.client.post(self.login_url, login_data)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('refresh', response.data)
		self.assertIn('access', response.data)
		self.assertIn('user', response.data)

	def test_user_login_with_invalid_credentials(self):
		login_data = {
			'username': 'nonexistentuser',
			'password': 'wrongpassword'
		}
		response = self.client.post(self.login_url, login_data)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class LogoutTestCase(TestCase):

	def setUp(self):
		self.client = APIClient()
		self.logout_url = reverse('logout')

	def test_logout(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out
		response = self.client.post(self.logout_url, {'refresh_token': str(refresh)})
		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_logout_without_refresh_token(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out without providing a refresh token
		response = self.client.post(self.logout_url)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_logout_with_invalid_token(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out with an invalid token
		response = self.client.post(self.logout_url, {'refresh_token': 'invalid_token'})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)        
 
class PasswordChangeTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.change_password_url = reverse('password_change')
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='oldpassword123'
		)
		self.refresh = RefreshToken.for_user(self.user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

	def test_change_password_success(self):
		data = {
			'old_password': 'oldpassword123',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		self.assertTrue(self.user.check_password('newpassword456'))

	def test_change_password_incorrect_old_password(self):
		data = {
			'old_password': 'wrongoldpassword',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.user.refresh_from_db()
		self.assertFalse(self.user.check_password('newpassword456'))

	def test_change_password_invalid_new_password(self):
		data = {
			'old_password': 'oldpassword123',
			'new_password': '123'  # Too short, should fail validation
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.user.refresh_from_db()
		self.assertFalse(self.user.check_password('123'))

	def test_change_password_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		data = {
			'old_password': 'oldpassword123',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_change_password_missing_fields(self):
		data = {
			'old_password': 'oldpassword123'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

		data = {
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class DeleteAccountTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='testpass123'
		)
		self.friend = User.objects.create_user(
			username='friend',
			email='friend@example.com',
			password='friendpass123'
		)
		self.refresh = RefreshToken.for_user(self.user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

		# Create a test avatar
		avatar = SimpleUploadedFile("test_avatar.jpg", b"file_content", content_type="image/jpeg")
		self.user.avatar = avatar
		self.user.save()

		# Add friend and other relations
		self.user.friends.add(self.friend)
		self.user.incoming_requests.add(self.friend)
		self.user.outgoing_requests.add(self.friend)
		self.user.blocked_users.add(self.friend)

		# Create a TwoFactorCode for the user
		TwoFactorCode.objects.create(user=self.user, code='123456')

	def test_delete_account_unauthenticated(self):
		url = reverse('delete-account')
		self.client.credentials()  # Remove authentication
		response = self.client.delete(url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertTrue(User.objects.filter(username='testuser').exists())

	def test_delete_account_invalid_token(self):
		url = reverse('delete-account')
		self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken123')
		response = self.client.delete(url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertTrue(User.objects.filter(username='testuser').exists()) 

	def test_delete_account_success(self):
		url = reverse('delete-account')
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')
		response = self.client.delete(url)
		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(User.objects.filter(username='testuser').exists())


	def test_delete_account_comprehensive(self):
		url = reverse('delete-account')
		response = self.client.delete(url)
		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

		# Check if user is deleted
		with self.assertRaises(User.DoesNotExist):
			User.objects.get(username='testuser')

		# Check if avatar file is deleted
		avatar_path = os.path.join(settings.MEDIA_ROOT, self.user.avatar.name)
		self.assertFalse(os.path.exists(avatar_path))

		# Check if relations are deleted
		self.assertEqual(self.friend.friends.count(), 0)
		self.assertEqual(self.friend.incoming_requests.count(), 0)
		self.assertEqual(self.friend.outgoing_requests.count(), 0)
		self.assertEqual(self.friend.blocked_users.count(), 0)

		# Check if TwoFactorCode is deleted
		self.assertEqual(TwoFactorCode.objects.filter(user=self.user).count(), 0)

	def tearDown(self):
		# Clean up any files created during the test
		if self.user.avatar:
			if os.path.isfile(self.user.avatar.path):
				os.remove(self.user.avatar.path)


class ProfileUpdateTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.profile_update_url = reverse('profile-update')
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='testpass123',
			first_name='Test',
			last_name='User'
		)
		self.refresh = RefreshToken.for_user(self.user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

	def test_profile_update_success(self):
		data = {
			'first_name': 'Updated',
			'last_name': 'Name',
			'email': 'updated@example.com'
		}
		response = self.client.put(self.profile_update_url, data)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		self.assertEqual(self.user.first_name, 'Updated')
		self.assertEqual(self.user.last_name, 'Name')
		self.assertEqual(self.user.email, 'updated@example.com')

	def test_profile_update_email_already_exists(self):
		User.objects.create_user(username='anotheruser', email='existing@example.com', password='pass123')
		data = {
			'email': 'existing@example.com'
		}
		response = self.client.put(self.profile_update_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('email', response.data)

	def test_profile_update_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		data = {
			'first_name': 'Updated',
		}
		response = self.client.put(self.profile_update_url, data)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class UserTestCase(TestCase):
	
	def setUp(self):
		self.client = APIClient()
		self.users_url = reverse('users')
		self.user1 = User.objects.create_user(username='testuser1', email='testuser1@example.com', password='testpass123')
		self.user2 = User.objects.create_user(username='testuser2', email='testuser2@example.com', password='testpass123')

	def test_get_all_users_authenticated(self):
		refresh = RefreshToken.for_user(self.user1)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		response = self.client.get(self.users_url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 2)  # Assuming only the two users created in setUp

	def test_get_all_users_unauthenticated(self):
		response = self.client.get(self.users_url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_specific_user_authenticated(self):
		refresh = RefreshToken.for_user(self.user1)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser2'}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['username'], 'testuser2')
		self.assertEqual(response.data['email'], 'testuser2@example.com')

	def test_get_me_authenticated(self):
		refresh = RefreshToken.for_user(self.user1)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		response = self.client.get(reverse('me'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['username'], 'testuser1')
		self.assertEqual(response.data['email'], 'testuser1@example.com')

	def test_get_me_unauthenticated(self):
		response = self.client.get(reverse('me'))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_specific_user_not_found(self):
		refresh = RefreshToken.for_user(self.user1)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		response = self.client.get(reverse('user-detail', kwargs={'username': 'nonexistentuser'}))
		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

	def test_get_specific_user_unauthenticated(self):
		response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser1'}))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_profile_invalid_token(self):
		self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken123')
		response = self.client.get(self.users_url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_profile_authenticated(self):
		refresh = RefreshToken.for_user(self.user1)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser1'}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['username'], 'testuser1')
		self.assertEqual(response.data['email'], 'testuser1@example.com')


def create_image():
	file = io.BytesIO()
	image = Image.new('RGB', (100, 100), color='red')
	image.save(file, 'png')
	file.name = f'test_{timezone.now().timestamp()}.png'
	file.seek(0)
	return file

class AvatarTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = User.objects.create_user(
			username='testuser', 
			email='test@example.com', 
			password='testpass123'
		)
		self.client.force_authenticate(user=self.user)
		self.url = reverse('upload-avatar')

	@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
	def test_successful_avatar_upload(self):
		image = create_image()
		response = self.client.post(self.url, {'avatar': image}, format='multipart')
		
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		self.assertTrue(self.user.avatar)
		self.assertTrue(default_storage.exists(self.user.avatar.name))

	@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
	def test_invalid_file_type(self):
		text_file = SimpleUploadedFile("test.txt", b"hello world", content_type="text/plain")
		response = self.client.post(self.url, {'avatar': text_file}, format='multipart')
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_missing_avatar_field(self):
		response = self.client.post(self.url, {}, format='multipart')
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
	def test_update_existing_avatar(self):
		# First upload
		image1 = create_image()
		response1 = self.client.post(self.url, {'avatar': image1}, format='multipart')
		self.assertEqual(response1.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		old_avatar_path = self.user.avatar.path
		old_avatar_name = os.path.basename(old_avatar_path)
	
		# Wait a bit to ensure file operations are complete
		time.sleep(1)
	
		# Second upload
		image2 = create_image()
		response2 = self.client.post(self.url, {'avatar': image2}, format='multipart')
		self.assertEqual(response2.status_code, status.HTTP_200_OK)
	
		# Wait a bit to ensure file operations are complete
		time.sleep(1)
	
		self.user.refresh_from_db()
		new_avatar_path = self.user.avatar.path
		new_avatar_name = os.path.basename(new_avatar_path)
	
		self.assertNotEqual(old_avatar_name, new_avatar_name)
		self.assertFalse(os.path.exists(old_avatar_path))
		self.assertTrue(os.path.exists(new_avatar_path))

class FriendManagementTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='testpass123')
		self.user2 = User.objects.create_user(username='user2', email='user2@example.com', password='testpass123')
		self.user3 = User.objects.create_user(username='user3', email='user3@example.com', password='testpass123')

	def get_tokens_for_user(self, user):
		refresh = RefreshToken.for_user(user)
		return str(refresh.access_token)

	def authenticate(self, user):
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_tokens_for_user(user)}')

	def test_send_friend_request(self):
		self.authenticate(self.user1)
		# response = self.client.post(reverse('friend-request', kwargs={'user_identifier': self.user2.id}))
		response = self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertTrue(self.user1 in self.user2.incoming_requests.all())
		self.assertTrue(self.user2 in self.user1.outgoing_requests.all())

	def test_send_friend_request_to_nonexistent_user(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('friend-request', kwargs={'username': 9999}))
		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

	def test_send_duplicate_friend_request(self):
		self.authenticate(self.user1)
		self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		response = self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertEqual(response.data['error'], "Friend request already sent.")
		self.assertTrue(self.user1 in self.user2.incoming_requests.all())
		self.assertTrue(self.user2 in self.user1.outgoing_requests.all())

	def test_accept_friend_request(self):
		self.user2.incoming_requests.add(self.user1)
		self.user1.outgoing_requests.add(self.user2)
		self.authenticate(self.user2)
		response = self.client.post(reverse('friend-response', kwargs={'username': self.user1.username}), {'action': 'accept'})
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertTrue(self.user1 in self.user2.friends.all())
		self.assertTrue(self.user2 in self.user1.friends.all())
		self.assertFalse(self.user1 in self.user2.incoming_requests.all())
		self.assertFalse(self.user2 in self.user1.outgoing_requests.all())

	def test_reject_friend_request(self):
		self.user2.incoming_requests.add(self.user1)
		self.user1.outgoing_requests.add(self.user2)
		self.authenticate(self.user2)
		response = self.client.post(reverse('friend-response', kwargs={'username': self.user1.username}), {'action': 'reject'})
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user1 in self.user2.friends.all())
		self.assertFalse(self.user2 in self.user1.friends.all())
		self.assertFalse(self.user1 in self.user2.incoming_requests.all())
		self.assertFalse(self.user2 in self.user1.outgoing_requests.all())

	def test_invalid_friend_request_response(self):
		self.user2.incoming_requests.add(self.user1)
		self.authenticate(self.user2)
		response = self.client.post(reverse('friend-response', kwargs={'username': self.user1.username}), {'action': 'invalid'})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_cancel_friend_request(self):
		self.user2.incoming_requests.add(self.user1)
		self.user1.outgoing_requests.add(self.user2)
		self.authenticate(self.user1)
		response = self.client.post(reverse('cancel-friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user1 in self.user2.incoming_requests.all())
		self.assertFalse(self.user2 in self.user1.outgoing_requests.all())

	def test_cancel_nonexistent_friend_request(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('cancel-friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_get_friend_list(self):
		self.user1.friends.add(self.user2)
		self.authenticate(self.user1)
		response = self.client.get(reverse('friend-list'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 1)
		self.assertEqual(response.data[0]['username'], 'user2')

	def test_get_friend_requests(self):
		self.user1.outgoing_requests.add(self.user2)
		self.user2.incoming_requests.add(self.user1)
		self.user3.outgoing_requests.add(self.user1)
		self.user1.incoming_requests.add(self.user3)
		self.authenticate(self.user1)
		response = self.client.get(reverse('friend-requests'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data['incoming']), 1)
		self.assertEqual(len(response.data['outgoing']), 1)
		self.assertEqual(response.data['incoming'][0]['username'], 'user3')
		self.assertEqual(response.data['outgoing'][0]['username'], 'user2')

	def test_unauthenticated_access(self):
		self.client.credentials()  # Clear authentication
		response = self.client.get(reverse('friend-list'))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

		response = self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

		response = self.client.post(reverse('friend-response', kwargs={'username': self.user1.username}), {'action': 'accept'})
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

		response = self.client.post(reverse('cancel-friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

		response = self.client.get(reverse('friend-requests'))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class BlockFeatureTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='testpass123')
		self.user2 = User.objects.create_user(username='user2', email='user2@example.com', password='testpass123')
		self.user3 = User.objects.create_user(username='user3', email='user3@example.com', password='testpass123')

	def authenticate(self, user):
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

	def test_block_user(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertTrue(self.user2 in self.user1.blocked_users.all())

	def test_block_nonexistent_user(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': 'nonexistentuser'}))
		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

	def test_block_self(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user1.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_block_already_blocked_user(self):
		self.authenticate(self.user1)
		self.user1.blocked_users.add(self.user2)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)  # It's okay to block an already blocked user

	def test_unblock_user(self):
		self.authenticate(self.user1)
		self.user1.blocked_users.add(self.user2)
		response = self.client.post(reverse('unblock-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user2 in self.user1.blocked_users.all())

	def test_unblock_not_blocked_user(self):
		self.authenticate(self.user1)
		response = self.client.post(reverse('unblock-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_get_blocked_users_list(self):
		self.authenticate(self.user1)
		self.user1.blocked_users.add(self.user2, self.user3)
		response = self.client.get(reverse('blocked-users-list'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 2)
		self.assertIn(self.user2.username, [user['username'] for user in response.data])
		self.assertIn(self.user3.username, [user['username'] for user in response.data])

	def test_block_removes_friend(self):
		self.user1.friends.add(self.user2)
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user2 in self.user1.friends.all())
		self.assertFalse(self.user1 in self.user2.friends.all())

	def test_block_cancels_outgoing_friend_request(self):
		self.user1.outgoing_requests.add(self.user2)
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user2 in self.user1.outgoing_requests.all())

	def test_block_cancels_incoming_friend_request(self):
		self.user1.incoming_requests.add(self.user2)
		self.authenticate(self.user1)
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertFalse(self.user2 in self.user1.incoming_requests.all())

	def test_cannot_send_friend_request_to_blocked_user(self):
		self.authenticate(self.user1)
		self.user1.blocked_users.add(self.user2)
		response = self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_cannot_send_friend_request_to_user_who_blocked_you(self):
		self.authenticate(self.user1)
		self.user2.blocked_users.add(self.user1)
		response = self.client.post(reverse('friend-request', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_unauthenticated_block_attempt(self):
		response = self.client.post(reverse('block-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_unauthenticated_unblock_attempt(self):
		response = self.client.post(reverse('unblock-user', kwargs={'username': self.user2.username}))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_unauthenticated_blocked_users_list_attempt(self):
		response = self.client.get(reverse('blocked-users-list'))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GDPRComplianceTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='testpass123'
		)
		self.refresh = RefreshToken.for_user(self.user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

	def test_anonymize_data(self):
		url = reverse('anonymize-data')
		response = self.client.post(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		self.assertTrue(self.user.username.startswith('Anonymous_'))
		self.assertTrue(self.user.email.startswith('anonymous_'))
		self.assertEqual(self.user.first_name, 'Anonymous')
		self.assertEqual(self.user.last_name, 'User')

	def test_gdpr_dashboard(self):
		url = reverse('gdpr-dashboard')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('username', response.data)
		self.assertIn('email', response.data)
		self.assertIn('data_management_options', response.data)
		self.assertIn('privacy_policy', response.data)

		options = response.data['data_management_options']
		self.assertIn('view_profile', options)
		self.assertIn('edit_profile', options)
		self.assertIn('change_avatar', options)
		self.assertIn('delete_account', options)
		self.assertIn('anonymize_data', options)

	def test_data_privacy_rights(self):
		url = reverse('data-privacy-rights')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('gdpr_dashboard', response.data)
		self.assertIn('view_profile', response.data)
		self.assertIn('edit_profile', response.data)
		self.assertIn('change_avatar', response.data)
		self.assertIn('delete_account', response.data)
		self.assertIn('anonymize_data', response.data)
		self.assertIn('privacy_policy', response.data)

	def test_privacy_policy_link(self):
		url = reverse('data-privacy-rights')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('privacy_policy', response.data)
		self.assertTrue(response.data['privacy_policy'].startswith('http'))

	def test_anonymize_data_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		url = reverse('anonymize-data')
		response = self.client.post(url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_gdpr_dashboard_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		url = reverse('gdpr-dashboard')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_data_privacy_rights_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		url = reverse('data-privacy-rights')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_gdpr_dashboard_links_valid(self):
		url = reverse('gdpr-dashboard')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		options = response.data['data_management_options']
		for key, value in options.items():
			if key != 'privacy_policy':
				response = self.client.get(value)
				self.assertNotEqual(response.status_code, status.HTTP_404_NOT_FOUND, f"{key} returned 404")

	def test_data_privacy_rights_links_valid(self):
		url = reverse('data-privacy-rights')
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		for key, value in response.data.items():
			if key != 'privacy_policy':
				response = self.client.get(value)
				self.assertNotEqual(response.status_code, status.HTTP_404_NOT_FOUND, f"{key} returned 404")
