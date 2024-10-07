import json
from channels.generic.websocket import AsyncWebsocketConsumer
from authentication .models import User
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async
from asgiref.sync import async_to_sync
from chat.models import message
from .Serializers import __messageSerializer__ ,__user_serializer__
from django.core.exceptions import ObjectDoesNotExist
from dateutil.parser import parse
from django.utils import timezone
from django.db.models import Q
from user_management .models import BlockedUsers
from datetime import datetime
import pytz
from .views import format_date
import openai
from django.shortcuts import get_object_or_404
from dotenv import load_dotenv
import os
from django.test import RequestFactory
from .views import RetreiveContacts
import base64
from django.core.files.base import ContentFile
from faker import Faker
import random


load_dotenv()
API_KEY= os.getenv('api_key')

client = openai.OpenAI(
    api_key=API_KEY,
    base_url="https://api.aimlapi.com",
)

class ChatBotConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope['user'].is_anonymous:
            await self.close()

        self.sender_id = self.scope['user'].id
        self.room_group_name = f'{self.sender_id}_withBot'

        await (self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )
        self.messages = [ {"role" : "system", "content": "You are a king helpful assistant."} ]
        await self.accept()
        
    async def disconnect(self, __quitcode__):
        await (self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
        )
        )
            
    async def receive(self, text_data=None):
        self.msgData = json.loads(text_data)
        if self.msgData.get('type') == 'send_to_bot' :
            await (self.channel_layer.group_send)(
                    f'{self.sender_id}_withBot',{
                    'type': 'bot_msg',
                    'message': self.msgData.get('message') })
            
            limiter = 'please give me a quick resume on 2 lines as maximum'
            self.messages.append({"role" : "user", "content" : self.msgData.get('message').get('content') + limiter})
            try :
                chat_completion = client.chat.completions.create(
                model="mistralai/Mistral-7B-Instruct-v0.2",
                    messages=self.messages,
                    temperature=0.7,
                    max_tokens=128,
                )
                response = chat_completion.choices[0].message.content
                await (self.channel_layer.group_send)(
                  f'{self.sender_id}_withBot',{
                        'type': 'bot_msg',
                        'message': {
                            "sender_id" : 0,
                            "receiver_id" : self.sender_id,
                            "content"   : response,
                            "color"     : "#fefeff",
                            "created_at" : datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M:%S")
                        }    
                })
                self.messages.append({"role" : "assistant", "content" : response})
            except Exception as e:
                await (self.channel_layer.group_send)(
                  f'{self.sender_id}_withBot',{
                        'type': 'bot_msg',
                        'message': {
                            "sender_id" : 0,
                            "receiver_id" : self.sender_id,
                            "content"   : "Error while getting response from AI try later",
                            "color"     : "red",
                            "created_at" : datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M:%S")
                        }    
                })
    
    async def bot_msg(self, event):
        await (self.send( text_data=json.dumps(event) ))

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope['user'].is_anonymous:
            await self.close()
        self.sender_id = self.scope['user'].id
        self.room_group_name = f'room_{self.sender_id}'
        await (self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )

        await self.broadcast_status_update(True)
        await self.accept()

    async def disconnect(self, __quitcode__):
        await self.broadcast_status_update(False)
        await (self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
        )
        )

    async def broadcast_status_update(self, online):
        status = True if online else False
        online_contacted_users = await self.retreive_contacted_users()
        if len(online_contacted_users):
            [await self.status_acknowledgment(user.get('id'), status) for user in online_contacted_users]

    async def status_acknowledgment(self, user_id, status):
        await self.channel_layer.group_send(
            f'room_{user_id}',{
                'type'    : 'status_update',
                'message' : {
                    'status_owner' : self.sender_id,
                    'status'       : status,
                }
            }
        )
    
    async def status_update(self, event):
        await (self.send( text_data=json.dumps(event) ))

    @database_sync_to_async
    def retreive_contacted_users(self):
        factory = RequestFactory()
        user = User.objects.get(id=self.sender_id)
        request = factory.get('/chat/GetContactSection/')
        request.user = user
        response = RetreiveContacts(request)
        response.render()
        contacted_users = json.loads(response.content.decode('utf-8'))
        online_contacted_users = [user for user in contacted_users if user.get('status') == True]
        return online_contacted_users

    async def receive(self, text_data=None):
        self.extracted_msg = json.loads(text_data)

        # 2 cases already Existing ChatList - Create new Conversation !
        if (self.extracted_msg.get('type') == '_start_chat_'):
            await self.start_chat()
        
        if (self.extracted_msg.get('type') == 'Update_msgStatus'):
            await self.update_unique_msg_status()
        
        if (self.extracted_msg.get('type') == '_mark_msgs_asRead_'):
            await self.processRead_Event(self.sender_id, self.extracted_msg.get('messageData').get('With'))
        # add if users are blocked or not !
        if (self.extracted_msg.get('type') == 'newchat.message'):
            await self.Broadcast_newMsg()

        if (self.extracted_msg.get('type') == 'typing_event'):
            await self.handleTypingEvent()

        if (self.extracted_msg.get('type') == 'deactivate_typing_event'):
            receiver = self.extracted_msg.get('messageData').get('receiver_id')
            await (self.channel_layer.group_send)(
                    f'room_{receiver}',{
                    'type': 'deactivate_typing_event',
                    'message': self.extracted_msg.get('messageData')
                }
                )
            
    async def deactivate_typing_event(self, event):
        await (self.send( text_data=json.dumps(event) ))
        
    async def handleTypingEvent(self):
        sender = self.extracted_msg.get('messageData').get('sender_id')
        receiver = self.extracted_msg.get('messageData').get('receiver_id')
        
        senderBlockedreceiver = await self.check_blockStatus(sender, receiver)
        receiverBlockedSender = await self.check_blockStatus(receiver, sender)

        if not senderBlockedreceiver and not receiverBlockedSender:
            AlreadyTalked = await self.already_have_record(sender, receiver)
            if AlreadyTalked:
                await (self.channel_layer.group_send)(
                    f'room_{receiver}',{
                    'type': 'receive_typing',
                    'message': self.extracted_msg.get('messageData')
                }
                )

    async def receive_typing(self, event):
        await (self.send( text_data=json.dumps(event) ))
        
    @database_sync_to_async
    def already_have_record (self, sender, receiver) :
        return message.objects.filter((Q(sender_id=receiver) & Q(receiver_id=sender)) |
                                      (Q(sender_id=sender) & Q(receiver_id=receiver))).exists()

    async def start_chat(self):
        Isconversation_exist = await self.get_record_if_exist()
        if (Isconversation_exist):
            await self.channel_layer.group_send(
            f"room_{self.sender_id}",{
                  'type': 'Pick_existed_conv',
                  'message': self.extracted_msg.get('messageData')
            }
            )
        else:
            sender_block_profilOwner = await self.check_blockStatus(self.sender_id, self.profil_Id)
            if sender_block_profilOwner:
                await self.channel_layer.group_send(
                    f"room_{self.sender_id}",{
                        'type': 'Blocke_Warning',
                        'message': self.extracted_msg.get('messageData')
                    }
                )
            else:
                await self.Process_First_msg()
                
    async def Process_First_msg(self):
        self.MSGsender = await self.get_obj_ById(self.sender_id)
        self.MSGreceiver = await self.get_obj_ById(self.profil_Id)
        ContactData = {
            "id"             :  self.MSGreceiver.id,
            "avatar"         :  self.MSGreceiver.avatar.url,
            "username"       :  self.MSGreceiver.username,
            "unreadMessages" : 0,
            "lastMessage"    : 'Say Hi 👋',
            "created_at"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "lastTime"       : format_date(datetime.now()),
            "status"         : self.MSGreceiver.is_online,
            "SenderData"     : __user_serializer__(self.MSGsender).data
        }
        await (self.channel_layer.group_send)(
            f'room_{self.sender_id}',{
                'type': 'start_Firstconv',
                'message': ContactData
            }
            )
    
    async def start_Firstconv(self, event):
        await (self.send( text_data=json.dumps(event) ))

    @database_sync_to_async
    def get_obj_ById(self, _id_):
        return User.objects.get(id=_id_)

    async def Blocke_Warning(self, event):
        await (self.send( text_data=json.dumps(event) ))

    @database_sync_to_async
    def check_blockStatus(self, blocker_id, blocked_id):
        blocker = User.objects.get(id=blocker_id)
        blocked = User.objects.get(id=blocked_id)
        is_blocked = BlockedUsers.objects.filter(Q(blocker=blocker, blocked=blocked)).exists()
        return is_blocked
    
    async def Pick_existed_conv(self, event):
        await (self.send( text_data=json.dumps(event) ))
        
    @database_sync_to_async
    def get_record_if_exist(self):
        self.profil_Id = self.extracted_msg.get('messageData').get('user_id')
        return message.objects.filter((Q(sender_id=self.profil_Id) & Q(receiver_id=self.sender_id)) |
                                      (Q(sender_id=self.sender_id) & Q(receiver_id=self.profil_Id))).exists()
        
    async def processRead_Event(self, currentUserId, FriendUsername):
        try:
            FriendId = await self.get_user_id(FriendUsername)
        except ObjectDoesNotExist:
            print(f"User with username {FriendUsername} does not exist")
        # all records where friendId is the sender and I'm the receiver !
        await self.update_messages(FriendId, currentUserId)

        await self.channel_layer.group_send(
          f"room_{currentUserId}",{
                  'type': 'msgs.areReaded',
                  'message': {
                        "all_readed_From" : FriendUsername
                  }
           }
        )
    
    @database_sync_to_async
    def get_user_status(self, user_id):
        userObj = get_object_or_404(User, pk=user_id)
        return userObj.is_online

    async def Broadcast_newMsg(self):
        self.receiver_id = self.extracted_msg.get('messageData').get('receiver_id')

        senderBlockedreceiver = await self.check_blockStatus(self.sender_id, self.receiver_id)
        receiverBlockedSender = await self.check_blockStatus(self.receiver_id, self.sender_id)
        if not senderBlockedreceiver and not receiverBlockedSender:
            already_have_conv = await self.already_have_record(self.sender_id, self.receiver_id)
            saved_message = await self.save_to_db()
            try :
                receiver_status = await self.get_user_status(self.receiver_id);
                if receiver_status :
                    await (self.channel_layer.group_send)(
                        f'room_{self.receiver_id}',{
                            'type': 'newchat.message',
                            'message' : saved_message
                        }
                        )
                    if already_have_conv :
                        await (self.channel_layer.group_send)(
                            f'room_{self.receiver_id}',{
                                'type': 'last.message',
                                'message' : saved_message
                            }
                            )
                if (self.receiver_id != self.extracted_msg.get('messageData').get('sender_id')):
                    await (self.channel_layer.group_send)(
                    f"room_{self.extracted_msg.get('messageData').get('sender_id')}",{
                            'type': 'newchat.message',
                            'message' : saved_message
                     }
                    )
                    await (self.channel_layer.group_send)(
                        f"room_{self.extracted_msg.get('messageData').get('sender_id')}",{
                              'type': 'last.message',
                            'message' : saved_message
                        }
                    )
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            await self.channel_layer.group_send(
            f"room_{self.sender_id}",{
                    'type': 'Blocke_Warning',
                    'message': None
                    }
                )

    @database_sync_to_async
    def get_user_id(self, username):
        return User.objects.get(username=username).id
    
    @database_sync_to_async
    def update_messages(self, sender_id, receiver_id):
        allrecord = message.objects.filter(sender_id=sender_id, receiver_id=receiver_id, seen=False)
        allrecord.update(seen=True)

    @database_sync_to_async
    def update_unique_msg_status(self):
        msgId = self.extracted_msg.get('messageData').get('id')
        requiredMsg = message.objects.filter(id=msgId)
        requiredMsg.update(seen=True)


    async def msgs_areReaded(self, event):
        await (self.send( text_data=json.dumps(event) ))
        
    async def newchat_message(self, event):
        await (self.send(text_data=json.dumps(event) ))
        
    async def last_message(self, event):
        await (self.send(
            text_data=json.dumps(event) ))
        
    @database_sync_to_async
    def save_to_db(self):
        self.msgDetails = self.extracted_msg.get('messageData')
        msgType = self.msgDetails.get('msgType')

        Usersender = User.objects.get(id=self.msgDetails.get('sender_id'))
        UserReceiver = User.objects.get(id=self.msgDetails.get('receiver_id'))
        
        if msgType == 'text':
            saved_model = message.objects.create(
                           sender_id=Usersender,
                           receiver_id = UserReceiver,
                           content= self.msgDetails.get('content'),
                           seen = self.msgDetails.get('seen'),
                        )
        elif msgType == 'image':
            fake = Faker()
            format, imgstr = self.msgDetails.get('ImgPath').split(';base64,')
            ext = format.split('/')[-1] 
            filename = fake.file_name() + '_' + str(random.randint(1, 10000)) + '.' + ext
            data = ContentFile(base64.b64decode(imgstr), name=filename)
            saved_model = message.objects.create(
                           sender_id=Usersender,
                           receiver_id = UserReceiver,
                           seen = self.msgDetails.get('seen'),
                           msgType= self.msgDetails.get('msgType'),
                           ImgPath=data,
                        )
        serialiser = __messageSerializer__(saved_model)
        return serialiser.data