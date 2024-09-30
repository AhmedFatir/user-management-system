from django.contrib.auth.models import AbstractUser
from django.db import models
import random, os, requests
from django.utils import timezone
from django.core.files.base import ContentFile


class CustomUser(AbstractUser):
	email = models.EmailField(unique=True)
	is_2fa_enabled = models.BooleanField(default=False)
	intra_id = models.CharField(max_length=100, unique=True, null=True, blank=True)
	avatar = models.ImageField(upload_to='avatars/', default='default.jpg')
	is_online = models.BooleanField(default=False)
	friends = models.ManyToManyField('self', symmetrical=True, blank=True)
	incoming_requests = models.ManyToManyField('self', symmetrical=False, related_name='outgoing_requests', blank=True)

	def save(self, *args, **kwargs):
		if self.pk:
			try:
				old_instance = CustomUser.objects.get(pk=self.pk)
				if old_instance.avatar != self.avatar:
					# Only delete the old avatar if it's not the default
					if old_instance.avatar and old_instance.avatar.name != 'default.jpg':
						if os.path.isfile(old_instance.avatar.path):
							os.remove(old_instance.avatar.path)
			except CustomUser.DoesNotExist:
				pass
		super().save(*args, **kwargs)

	def set_avatar_from_url(self, url):
		response = requests.get(url)
		if response.status_code == 200:
			# file_name = f"avatar_{self.id}.jpg"
			file_name = f"{self.username}_{self.id}.jpg"
			self.avatar.save(file_name, ContentFile(response.content), save=True)

	def __str__(self):
		return self.username


class TwoFactorCode(models.Model):
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
	code = models.CharField(max_length=6)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f"2FA code for {self.user.username}"

	@classmethod
	def generate_code(cls, user):
		code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
		return cls.objects.create(user=user, code=code)

	def is_valid(self):
		return timezone.now() - self.created_at < timezone.timedelta(minutes=10)