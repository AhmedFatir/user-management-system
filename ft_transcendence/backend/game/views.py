from django.shortcuts import render
from django.db import models
from django.db.models import Q
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import *
from .serializers import *
from user_management.models import Player, Notification
from authentication .models import User
from django.shortcuts import get_object_or_404

class CurrentUserGameHistoryView(APIView):
    def get(self, request):
        player_id = request.user.id
        queryset = GameHistory.objects.filter(
            models.Q(winner_user_id=player_id) | models.Q(loser_user_id=player_id)
        )
        serializer = GameHistorySerializer(queryset, many=True, context={'player_id': player_id})
        return Response(serializer.data, status=status.HTTP_200_OK)

class PlayerGameHistoryView(APIView):
    def get(self, request, player_id):
        queryset = GameHistory.objects.filter(
            models.Q(winner_user_id=player_id) | models.Q(loser_user_id=player_id)
        )
        serializer = GameHistorySerializer(queryset, many=True, context={'player_id': player_id})
        return Response(serializer.data, status=status.HTTP_200_OK)


class AchievementListView(APIView):
    def get(self, request):
        achievements = Achievement.objects.all()
        serializer = AchievementSerializer(achievements, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CurrentUserAchievementListView(APIView):
    permission_classes = [IsAuthenticated]  
    
    def get(self, request):
        user_achievements = UserAchievement.objects.filter(user=request.user)
        serializer = UserAchievementSerializer(user_achievements, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SpecificUserAchievementListView(APIView):
    def get(self, request, user_id):
        user_achievements = UserAchievement.objects.filter(user_id=user_id)
        serializer = UserAchievementSerializer(user_achievements, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TriggerAchievementView(APIView):
    def post(self, request):
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "achievements_group",
            {
                "type": "send_achievement",
                "achievement": {
                    "title": "Achievement Unlocked!",
                    "description": "You have completed 5 games."
                }
            }
        )
        return Response({"status": "Achievement sent"}, status=status.HTTP_200_OK)
    
class GameSettingsView(APIView):
    def post(self, request):
        try:
            print(f"{request.data}")
            player, createdPlayer = Player.objects.get_or_create(user_id=request.user.id)
            game_settings, created = GameSettings.objects.get_or_create(user=player)
            if created:
                print("A new GameSettings instance was created.")
            else:
                print("An existing GameSettings instance was retrieved.")
            serializer = GameSettingsSerializer(instance=game_settings, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Player.DoesNotExist:
            return Response({"error": "Player not found"}, status=status.HTTP_404_NOT_FOUND)
    def get(self, request):
        try:
            player = Player.objects.get(user_id=request.user.id)
            game_settings = GameSettings.objects.get(user=player)
            serializer = GameSettingsSerializer(game_settings)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Player.DoesNotExist:
            return Response({"error": "Player not found"}, status=status.HTTP_404_NOT_FOUND)
        except GameSettings.DoesNotExist:
            return Response({"error": "GameSettings not found"}, status=status.HTTP_404_NOT_FOUND)
        
class GameRoomView(APIView):
    def get(self, request, room_id):
        try:
            room = GameRoom.objects.get(id=room_id)
            print(f"{room.player1}")
            print(f"{room.player2}")
            serializer = GameRoomSerializer(room)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except GameRoom.DoesNotExist:
            return Response({"error": "Game room not found"}, status=status.HTTP_404_NOT_FOUND)

class SendChallengeView(APIView):
    def post(self, request):
        player_receiver_id = request.data.get('player_receiver_id')
        
        if not player_receiver_id:
            return Response({'error': 'player_receiver_id is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            player_receiver = get_object_or_404(User, id=player_receiver_id)
            player_sender = request.user
            player1, created= Player.objects.get_or_create(user_id=request.user.id)
            player2, created = Player.objects.get_or_create(user_id=player_receiver_id)
            try:
                invite_game_room, created = InviteGameRoom.objects.get_or_create(player1=player1, player2=player2)
                game_challenge = GameChallenge.objects.create(
                    player_sender=player_sender,
                    player_receiver=player_receiver,
                    invite_game_room=invite_game_room
                )
            except Exception as e:
                print(f"Error creating InviteGameRoom: {e}")
            Notification.objects.create (
                recipient=player_receiver,
                sender=player_sender,
                message='has challenged you to a game!'
            )
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{player_receiver.id}',
                {
                    'type': 'notification_match',
                    'message': f'{player_sender.username} has invited you to play a game.',
                    'sender': player_sender.id, 
                }
            )
            return Response({'message': 'Challenge sent successfully.'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'Player not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Player.DoesNotExist:
            return Response({'error': 'Player instance not found for the sender or receiver.'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class GameChallengeResponse(APIView):
    def patch(self, request, sender_id):
        print("hello world")
        player_sender = get_object_or_404(User, id=sender_id)
        player_receiver = request.user
    
        game_challenge = get_object_or_404(GameChallenge, player_sender=player_sender, player_receiver=player_receiver)


        if game_challenge.status != 'P':
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
    
        action = request.data.get('status')
        if action not in ['accepted', 'rejected']:
            game_challenge.delete()
            return Response({'error': 'Invalid action. Choose "accepted" or "rejected".'}, status=status.HTTP_400_BAD_REQUEST)
        
        if action == 'accepted':
            game_challenge.status = 'A'
            game_challenge.save()
            game_challenge.delete()
            invite_game_room = game_challenge.invite_game_room
            invite_game_room.player2 = Player.objects.get(user=player_receiver)
            invite_game_room.save()
            print("InviteGameRoom is created")
            return Response({'message': 'Game challenge accepted.'}, status=status.HTTP_200_OK)
        
        elif action == 'rejected':
            game_challenge.status = 'D'
            game_challenge.save()
            invite_game_room = game_challenge.invite_game_room
            invite_game_room.delete()
            game_challenge.delete()
            print(f"invite_game_room && game_challenge are deleted")
            return Response({'message': 'Game challenge rejected.'}, status=status.HTTP_200_OK)

class GameInvitationResponse(APIView):
    def post(self, request, invited):
        oppenent = get_object_or_404(User, id=invited);
        current_user = request.user
        action = request.data.get('status')
        if action == 'accepted':
            message = f"{oppenent.username} has accept your game invitaion"
        elif action == 'rejected':
            message = f"{oppenent.username} has reject your game invitaion"
        Notification.objects.create(
                recipient=oppenent,
                sender=current_user,
                message=message
            )
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f'notifications_{current_user.id}',
            {
                'type': 'join_game',
                'message': message,
            }
        )
        return Response({'message': 'Game challenge accepted.'}, status=status.HTTP_200_OK)
    
class InviteGameRoomView(APIView):
    def get(self, request, room_id):
        try:
            room = InviteGameRoom.objects.get(id=room_id)
            print(f"{room.player1}")
            print(f"{room.player2}")
            serializer = InviteGameRoomSerializer(room)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except InviteGameRoom.DoesNotExist:
            return Response({"error": "Game room not found"}, status=status.HTTP_404_NOT_FOUND)

class TournamentGameRoomView(APIView):
    def get(self, request, room_id):
        try:
            room = TournamentGameRoom.objects.get(id=room_id)
            print(f"{room.player1}")
            print(f"{room.player2}")
            serializer = TournamentGameRoomSerializer(room)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except TournamentGameRoom.DoesNotExist:
            return Response({"error": "Game room not found"}, status=status.HTTP_404_NOT_FOUND)

class CheckInviteReconnection(APIView):
    def get(self, request):
        try:
            player = get_object_or_404(Player, user=request.user)
            room = InviteGameRoom.objects.filter(
                Q(player1=player) | Q(player2=player)
            ).first()

            if room:
                return Response({
                    'exists': True,
                    'room_id': room.id,
                    'player1': room.player1.user.username,
                    'player2': room.player2.user.username if room.player2 else None,
                    'is_waiting': room.is_waiting,
                }, status=status.HTTP_200_OK)
            else:
                return Response({ 'exists': False }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({ 'error': str(e) }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class LocalGameRoomCreateView(APIView):
    def post(self, request, format=None):
        player1_id = request.data.get('player1')
        player2_id = request.data.get('player2')
        arena = request.data.get('arena')

        if not all([player1_id, player2_id, arena]):
            return Response({'error': 'player1, player2, and arena are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            player1 = LocalPlayer.objects.get(id=player1_id)
            player2 = LocalPlayer.objects.get(id=player2_id)
        except LocalPlayer.DoesNotExist:
            return Response({'error': 'One or both players do not exist'}, status=status.HTTP_404_NOT_FOUND)

        game_room = LocalGameRoom.objects.create(
            player1=player1,
            player2=player2,
            arena=arena
        )
        
        serializer = LocalGameRoomSerializer(game_room)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def get(self, request, game_room_id):
        game_room = get_object_or_404(LocalGameRoom, id=game_room_id)
        serializer = LocalGameRoomSerializer(game_room)
        return Response(serializer.data)