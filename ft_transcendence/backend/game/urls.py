# urls.py
from django.urls import path
from .views import *

urlpatterns = [
    path('game-history/', CurrentUserGameHistoryView.as_view(), name='player-game-history'),
    path('game-history/<int:player_id>/', PlayerGameHistoryView.as_view(), name='player-game-history'),
    path('achievements/', AchievementListView.as_view(), name='achievement_list'),
    path('achievements/player/<int:user_id>', SpecificUserAchievementListView.as_view(), name='player_achievements'),
    path('achievements/me', CurrentUserAchievementListView.as_view(), name='player_achievements'),
    path('trigger-achievement/', TriggerAchievementView.as_view(), name='trigger_achievement'),
    path('game-settings/current-user/', GameSettingsView.as_view(), name='game_settings'),
    path('game-room/<int:room_id>', GameRoomView.as_view(), name='game_room'),
    path('send-challenge/', SendChallengeView.as_view(), name='send-challenge'),
    path('game-challenges/<int:sender_id>/response/', GameChallengeResponse.as_view(), name='game-challenge'),
    path('game-response/<int:invited>/', GameInvitationResponse.as_view(), name="game-response"),
    path('invite-game-room/<int:room_id>', InviteGameRoomView.as_view(), name='invite-game-room'),
    path('tournament-room/<int:room_id>', TournamentGameRoomView.as_view(), name='tournament-room'),
    path('check-invite-room', CheckInviteReconnection.as_view(), name="check-invite-room"),
    path('create-local-game-room/', LocalGameRoomCreateView.as_view(), name='create-local-game-room'),
    path('local-game-room/<int:game_room_id>/', LocalGameRoomCreateView.as_view(), name='get-local-game-room'),
]
