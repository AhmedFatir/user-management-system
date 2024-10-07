from .models import User
from rest_framework import serializers
from user_management.models import Player
from django.contrib.auth.password_validation import validate_password

def user_avatar_upload_path(instance, filename):
    return f"player/{instance.id}/user_avatar/{filename}"

class CurrentUserSerializer(serializers.ModelSerializer):
    avatar_type = serializers.CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ['id', 'avatar', 'username', 'email', 'avatar_type', 'is_online', 'api_42_id']


class CurrentUserSettingsSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    avatar_type = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'avatar', 'email', 'old_password', 'new_password', 'avatar_type']
        extra_kwargs = {
            'username': {'required': False},
            'email': {'required': False},
            'avatar': {'required': False},
        }
    def validate(self, data):
        user = self.context['request'].user
        if ('avatar_type' in data) and ('avatar' in data):
            raise serializers.ValidationError({"avatar": "there is 2 avatars provided ghayerha"})
        if 'new_password' in data:
            if not user.check_password(data.get('old_password')):
                raise serializers.ValidationError({"old_password": "Old password is not correct"})
            if data['new_password'] == data['old_password']:
                raise serializers.ValidationError({"new_password": "New password cannot be the same as the old password"})
        return data
    
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.avatar = validated_data.get('avatar', instance.avatar)
        instance.email = validated_data.get('email', instance.email)
        if 'new_password' in validated_data:
            instance.set_password(validated_data['new_password'])
        if 'avatar_type' in validated_data:
            avatar_type = validated_data.get('avatar_type')
            instance.avatar = f'avatars/{avatar_type}.png'
        instance.save()
        return instance


class UserRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    avatar_type = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['avatar', 'username', 'email', 'password', 'confirm_password', 'avatar_type']
        extra_kwargs = {"password": {"write_only": True}}
    
    def validate(self, data):
        if(data['password'] != data['confirm_password']):
            raise serializers.ValidationError({'password': 'Passwords must match.'})
        return data

    def create(self, validated_data):
        confirm_password = validated_data.pop('confirm_password')
        avatar_type = validated_data.pop('avatar_type', None)
        if avatar_type:
            validated_data['avatar'] = f'avatars/{avatar_type}.png'
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user
        