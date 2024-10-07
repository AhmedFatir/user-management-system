from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.
from user_management.models import Player
import pyotp



class User(AbstractUser):
    email = models.EmailField(unique=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    api_42_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_online = models.BooleanField(default=False)
    is_2fa_enabled = models.BooleanField(default=False)
    is_2fa_verified = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=255, null=True, blank=True)
    
    def save(self, *args, **kwargs):
        created = self.pk is None
        super().save(*args, **kwargs)
        if created:
            Player.objects.create(user=self)
    
    def set_avatar_from_url(self, image_url):
        from urllib import request
        from django.core.files import File
        import os
        result = request.urlretrieve(image_url)
        self.avatar.save(
            os.path.basename(image_url),
            File(open(result[0], 'rb'))
        )

    def generate_otp_secret(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
            self.save()

    # Method to get the provisioning URI for Google Authenticator
    def get_otp_uri(self):
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.email, issuer_name="PongyGame"
        )
    def __str__(self) -> str:
        return self.username