from django.db import models
from django.conf import settings
from django.db.models import Q
from authentication .models import User


# @ New Feat Add : 
    #  msgtype Field default text, or ""
    #  ImgPath Field ImageField null true blank true upload To chat_media

class message(models.Model):
    MSG_TYPE_CHOICES = [
    ('text', 'Text message'),
    ('image', 'Image message'),]
    
    sender_id   = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='message_sender', on_delete=models.CASCADE)
    receiver_id = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='message_receiver', on_delete=models.CASCADE)
    content     = models.TextField(null=True, blank=True)
    msgType     = models.CharField(max_length=5, choices=MSG_TYPE_CHOICES, default='text')
    ImgPath     = models.ImageField(upload_to='chat_images/', null=True, blank=True, max_length=2000)
    seen        = models.BooleanField(default=False)
    created_at  = models.DateTimeField(auto_now_add=True)
 
    def __str__(self) -> str:
        return f'from : {self.sender_id} to {self.receiver_id} with : {self.content} seen: {self.seen}, created_at : {self.created_at}'
    class Meta:
        ordering = ['-created_at']

    def GetUnreadmessages(currentUserId):
        return message.objects.filter(receiver_id=currentUserId, seen=False)

    def UnreadMessageBeetwen( currentUserID, user2_Id):
        if (currentUserID != user2_Id):
            return message.objects.filter(receiver_id=currentUserID, sender_id=user2_Id, seen=False).count()
        else:
            return 0
    
    def getLastMessage(currentUserId, user2_Id):
        return message.objects.filter((Q(sender_id=currentUserId) & Q(receiver_id=user2_Id)) |
                                      (Q(sender_id=user2_Id) & Q(receiver_id=currentUserId))).order_by('-created_at').first()
    def GetUserStatus(user_Id):
        return User.objects.filter(id=user_Id).first().is_online