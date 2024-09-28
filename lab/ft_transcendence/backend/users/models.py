from django.contrib.auth.models import AbstractUser
from django.db import models
import random
from django.utils import timezone

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_2fa_enabled = models.BooleanField(default=False)
    intra_id = models.CharField(max_length=100, unique=True, null=True, blank=True)

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