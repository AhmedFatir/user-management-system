from channels.generic.websocket import AsyncWebsocketConsumer
import json
from django.db.models import Q
from channels.db import database_sync_to_async
from django.shortcuts import get_object_or_404
from authentication.models import User

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope['user'].is_anonymous:
            await self.close()
        else:
            self.user = self.scope['user']
            self.room_group_name = f'notifications_{self.user.id}'
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            await self.set_user_status(True)
            await self.broadcast_status_update(True)
            await self.accept()

    async def disconnect(self, close_code):
        await self.set_user_status(False)  
        await self.broadcast_status_update(False) 
        
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, content):
        pass
        # message = content['message']
        # await self.send(text_data=json.dumps({
        #     'message': message
        # }))

    @database_sync_to_async
    def set_user_status(self, is_online):
        user = get_object_or_404(User, id=self.user.id)
        user.is_online = is_online
        user.save()

    async def broadcast_status_update(self, online):
        friends_ids = await self.get_user_friends()
        status = 'online' if online else 'offline'
        for friend_id in friends_ids: 
            group_name = f'notifications_{friend_id}'
            await self.channel_layer.group_send(
                group_name,
                {
                    'type': 'status_update',
                    'user_id': self.user.id,
                    'status': status
                }
            )

    @database_sync_to_async
    def get_user_friends(self):
        from .models import Friendship
        friendships = Friendship.objects.filter(Q(player=self.user) | Q(friend=self.user))
        friends_ids = [
            friendship.friend.id if friendship.player == self.user else friendship.player.id 
            for friendship in friendships
        ]
        return list(friends_ids)

    async def status_update(self, event):
        user_id = event['user_id']
        status = event['status']
        await self.send(text_data=json.dumps({
            'type': 'status_update',
            'user_id': user_id,
            'status': status
        }))

    async def join_game(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type' : 'join_game',
            'message': message
        }))
        
    async def notification_message(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type' : 'notification',
            'message': message
        }))

    async def notification_tournament(self, event):
        message = event['message']
        sender_id = event['sender']
        await self.send(text_data=json.dumps({
            'type' : 'tournament_notification',
            'message': message,
            'sender_id': sender_id
        }))

    async def invite_reconnection(self, event):
        print("HELLO BABY FROM NOTIFICATION INVITE RECONNECTION")
        message = event['message']
        sender = event['sender']
        receiver = event['receiver']
        await self.send(text_data=json.dumps({
            'type': 'invite_reconnection',
            'message': message,
            'sender': sender,
            'receiver': receiver
        }))

    async def notification_match(self, event):
        message = event['message']
        sender_id = event['sender']
        await self.send(text_data=json.dumps({
            'type' : 'match_notification',
            'message': message,
            'sender_id': sender_id
        }))

class EchoConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope['user'].is_anonymous:
            await self.close()
        else:
            await self.accept()
            
            print(f"User connected: {self.scope['user']}")

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        print(text_data)
        await self.send(text_data=json.dumps({
            'message': text_data
        }))





# from channels.generic.websocket import AsyncWebsocketConsumer
# import json
# from channels.db import database_sync_to_async


# class NotificationConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         if self.scope['user'].is_anonymous:
#             await self.close()
#         else:
#             self.user = self.scope['user']
#             self.room_group_name = f'notifications_{self.user.id}'
#             await self.channel_layer.group_add(
#                 self.room_group_name,
#                 self.channel_name
#             )
#             await self.set_user_status(True)
#             await self.broadcast_status_update(True)
#             await self.accept()

#     async def disconnect(self, close_code):
#         await self.set_user_status(False)
#         await self.broadcast_status_update(True)
#         await self.channel_layer.group_discard(
#             self.room_group_name,
#             self.channel_name
#         )

#     async def receive(self, content):
#         message = content['message']
#         await self.send(text_data=json.dumps({
#             'message': message
#         }))

#     @database_sync_to_async
#     def set_user_status(self, is_online):
#         self.user.is_online = is_online
#         self.user.save()


#     async def broadcast_status_update(self, online):
#         friends = self.get_user_friends()
#         status = 'online' if online else 'offline'
#         for friend in friends:
#             group_name = f'notifications_{friend.id}'
#             await self.channel_layer.group_send(
#                 group_name,
#                 {
#                     'type': 'status_update',
#                     'user_id': self.user.id,
#                     'status': status
#                 }
#             )

#     async def notification_message(self, event):
#         message = event['message']
#         await self.send(text_data=json.dumps({
#             'message': message
#         }))

#     async def status_update(self, event):
#         user_id = event['user_id']
#         status = event['status']
#         await self.send(text_data=json.dumps({
#             'type': 'status_update',
#             'user_id': user_id,
#             'status': status
#         }))

#     @database_sync_to_async
#     def get_user_friends(self):
#         from .models import Friendship
#         friendships = Friendship.objects.filter(player=self.user)
#         friends_ids = friendships.values_list('friend_id', flat=True)
#         return friends_ids



# class EchoConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         if self.scope['user'].is_anonymous:
#             await self.close()
#         else:
#             await self.accept()
            
#             print(f"User connected: {self.scope['user']}")

#     async def disconnect(self, close_code):
#         pass

#     async def receive(self, text_data):
#         print(text_data)
#         await self.send(text_data=json.dumps({
#             'message': text_data
#         }))
