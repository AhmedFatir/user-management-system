from game.consumers import GameConsumer
from user_management .consumers import NotificationConsumer
from chat .consumers import ChatConsumer, ChatBotConsumer

from django.urls import path

websocket_urlpatterns = [
    path('ws/game/', GameConsumer.as_asgi()),
    path('ws/notifications/', NotificationConsumer.as_asgi()),
    path('ws/chat/', ChatConsumer.as_asgi()),
    path('ws/chatbot/', ChatBotConsumer.as_asgi()),
]