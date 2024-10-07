from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Friendship


