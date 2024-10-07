from rest_framework import serializers
from .models import Player, Friendship, FriendInvitation, Notification
from authentication.serializers import CurrentUserSerializer
from .models import *

class FriendshipSerializer(serializers.ModelSerializer):
    friend = serializers.SerializerMethodField()

    class Meta:
        model = Friendship
        fields = [
            'friend', 
            'blocked'
            ]
    def get_friend(self, obj):
        return PlayerSerializer(obj.friend).data






class PlayerSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    avatar = serializers.ImageField(source='user.avatar')
    is_2fa_enabled = serializers.BooleanField(source='user.is_2fa_enabled')
    rank_progress = serializers.IntegerField(source='get_rank_progress')
    api_42_id = serializers.CharField(source='user.api_42_id')

    class Meta:
        model = Player
        fields = [
            'user_id',
            'is_2fa_enabled',
            'username',
            'avatar', 
            'rank', 
            'rank_progress', 
            'games_played', 
            'games_won', 
            'xp',
            'api_42_id'
            
        ]
    

class FriendInvitationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FriendInvitation
        fields = [
            'id', 
            'player_sender', 
            'player_receiver', 
            'invite_status', 
            'send_at']

    

class NotificationSerializer(serializers.ModelSerializer):
    sender_username = serializers.CharField(source='sender.username')
    sender_avatar = serializers.CharField(source='sender.avatar.url')

    class Meta:
        model = Notification
        fields = [
            'id', 
            'sender_id',
            'sender_username',
            'sender_avatar',
            'message', 
            'title', 
            'description', 
            'timestamp', 
            'is_read'
        ]



class TournamentSerializer(serializers.ModelSerializer):
    tournament_participants = CurrentUserSerializer(many=True, read_only=True)

    class Meta:
        model = Tournament
        fields = [
            'id', 
            'tournament_creator',
            'tournament_name',
            'tournament_prize',
            'tournament_map',
            'is_online',
            'created_at',
            'tournament_date',
            'tournament_status',
            'tournament_stage',
            'tournament_participants',
        ]

#check if the user is not present with the invited users
class TournamentInvitationSerializer(serializers.ModelSerializer):
    tournament = TournamentSerializer()
    class Meta:
        model = TournamentInvitation
        fields = [
            'id', 
            'tournament', 
            'player', 
            'invitation_status', 
            'invitation_date'
        ]

class TournamentCreateSerializer(serializers.ModelSerializer):
    invitedUsers = serializers.ListField(child=serializers.IntegerField())

    class Meta:
        model = Tournament
        fields = [
            'tournament_name', 
            'tournament_map', 
            'invitedUsers'
            ]

    def validate(self, data):
        maps = ['undergroundHell', 'undergroundForest', 'undergroundGraveyard']
        currentUser = self.context['request'].user
        if data['tournament_map'] not in maps:
            raise serializers.ValidationError({"tournament_map": "Invalid map name"})
        if len(data['invitedUsers']) != 3:
            raise serializers.ValidationError({"invitedUsers": "The number of invited players must be 3"})
        if Tournament.objects.filter(tournament_participants=currentUser).exists():
            raise serializers.ValidationError({"invitedUsers": "You are already present in a tournament"})
        if len(data['invitedUsers']) != len(set(data['invitedUsers'])):
            raise serializers.ValidationError({"invitedUsers": "Duplicate user IDs detected in the invited players list"})
        for user_id in data['invitedUsers']:
            if user_id == currentUser.id:
                raise serializers.ValidationError({"invitedUsers": "You cannot invite yourself to the tournament"})
            if Tournament.objects.filter(tournament_participants=user_id).exists():
                raise serializers.ValidationError({"invitedUsers": f"User with ID {user_id} is already present in another tournament"})

        return data


class TournamentParticipantsSerializer(serializers.ModelSerializer):

    class Meta:
        model = TournamentParticipants
        fields = '__all__'


# class LocalTournamentUserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = LocalTournamentUser
#         fields = ['id', 'username', 'avatar']


class LocalPlayerSerializer(serializers.ModelSerializer):
    class Meta:
        model = LocalPlayer
        fields = [
            'id', 
            'username', 
            'avatar', 
            'paddle_color', 
            'keys'
            ]

class LocalTournamentParticipantsSerializer(serializers.ModelSerializer):
    player1 = LocalPlayerSerializer()
    player2 = LocalPlayerSerializer()
    winner = LocalPlayerSerializer()
    loosers = LocalPlayerSerializer()

    class Meta:
        model = LocalTournamanetParticipants
        fields = [
            'id', 
            'player1',
            'player2',
            'matchPlayed',
            'matchStage',
            'winner',
            'loosers'
            ]

class LocalTournamentSerializer(serializers.ModelSerializer):
    tournament_participants = serializers.SerializerMethodField()

    class Meta:
        model = LocalTournament
        fields = [
            'id', 
            'tournament_creator', 
            'tournament_name', 
            'tournament_map',
            'created_at', 
            'tournament_status', 
            'tournament_stage',
            'is_online', 
            'tournament_participants'
            ]

    def get_tournament_participants(self, obj):
        participants = LocalTournamanetParticipants.objects.filter(tournament=obj)
        all_participants = []
        for participant in participants:
            all_participants.append(participant.player1)
            all_participants.append(participant.player2)

        return LocalPlayerSerializer(all_participants, many=True).data


class LocalTournamentCreatSerializer(serializers.ModelSerializer):
    invitedUsers = serializers.ListField(child=serializers.CharField())

    class Meta:
        model = LocalTournament
        fields = [
            'tournament_name',
            'tournament_map' ,
            'invitedUsers'
            ]

    def validate(self, data):
        #the invited users are just names of the user that not created yet 
        currentUser = self.context['request'].user
        if len(data['invitedUsers']) != 3:
            raise serializers.ValidationError({"invitedUsers": "The number of invited players must be 3"})
        # if LocalTournament.objects.filter(local_tournament_users=currentUser).exists():
        #     raise serializers.ValidationError({"invitedUsers": "You are already present in a local tournament"})
        if len(data['invitedUsers']) != len(set(data['invitedUsers'])):
            raise serializers.ValidationError({"invitedUsers": "Duplicate user IDs detected in the invited players list"})
        for user in data['invitedUsers']:
            if user == currentUser.username:
                raise serializers.ValidationError({"invitedUsers": "You cannot invite yourself to the local tournament"})

        return data



