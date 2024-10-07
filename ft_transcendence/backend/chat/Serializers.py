from rest_framework import serializers
from .models import message
from django.conf import settings
from django.db import models
from authentication .models import User

class __user_serializer__(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'avatar', 'username']
# @ New Feat Add : 
    # msgtype
    # ImgPath
class __messageSerializer__(serializers.ModelSerializer):
    class Meta:
        model  = message
        fields = ['id', 'sender_id', 'receiver_id','msgType','content','ImgPath', 'seen', 'created_at']