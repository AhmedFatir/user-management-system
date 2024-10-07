from django.contrib import admin
from . import models
# Register your models here.




admin.site.register(models.Player)
admin.site.register(models.FriendInvitation)
admin.site.register(models.Notification)
admin.site.register(models.Friendship)
admin.site.register(models.BlockedUsers)
admin.site.register(models.Tournament)
admin.site.register(models.TournamentInvitation)
admin.site.register(models.TournamentParticipants)
admin.site.register(models.XPHistory)
admin.site.register(models.LocalTournament)
admin.site.register(models.LocalPlayer)
admin.site.register(models.LocalTournamanetParticipants)

