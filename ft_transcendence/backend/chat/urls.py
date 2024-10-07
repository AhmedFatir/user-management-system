from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
        path('GetContactSection/', views.RetreiveContacts),
        path('GetMessageswith/<str:username>/', views.getMessageswith)
]