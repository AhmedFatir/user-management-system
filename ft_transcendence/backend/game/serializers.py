from rest_framework import serializers
from .models import *
from user_management.serializers import PlayerSerializer, LocalPlayerSerializer

class GameHistorySerializer(serializers.ModelSerializer):
    winner_user = PlayerSerializer()
    loser_user = PlayerSerializer()
    is_winner = serializers.SerializerMethodField()

    class Meta:
        model = GameHistory
        fields = ['id', 'winner_user', 'loser_user', 'winner_score', 'loser_score', 'game_type', 'match_type', 'played_at', 'is_winner']

    def get_is_winner(self, obj):
        player_id = self.context.get('player_id')
        return obj.winner_user_id == player_id

class AchievementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Achievement
        fields = ['id', 'title', 'description', 'image', 'task']


class UserAchievementSerializer(serializers.ModelSerializer):
    player = serializers.PrimaryKeyRelatedField(read_only=True)
    achievement = AchievementSerializer()

    class Meta:
        model = UserAchievement
        fields = ['player', 'achievement', 'achieved_at']

class GameSettingsSerializer(serializers.ModelSerializer):
    user_name = serializers.ReadOnlyField(source='user.user.username')
    class Meta:
        model = GameSettings
        fields = '__all__'
        read_only_fields = ['user']

class GameRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameRoom
        fields = ['id', 'player1', 'player2', 'is_waiting', 'created_at']

class GameChallengeSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameChallenge
        fields = '__all__'

class InviteGameRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = InviteGameRoom
        fields = '__all__'

class TournamentGameRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = TournamentGameRoom
        fields = '__all__'


class LocalGameRoomSerializer(serializers.ModelSerializer):
    player1 = LocalPlayerSerializer(read_only=True)
    player2 = LocalPlayerSerializer(read_only=True)

    class Meta:
        model = LocalGameRoom
        fields = '__all__'

 