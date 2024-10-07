from django.shortcuts import render
from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.utils import IntegrityError
from game.models import Achievement, UserAchievement
from authentication .models import User
from authentication .serializers import CurrentUserSerializer
from django.db.models import Q
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import HttpResponseForbidden
from .models import *
from .serializers import *
from django.db.models import Case, When, Value, IntegerField
from game.serializers import GameHistorySerializer, UserAchievementSerializer
from game.models import GameHistory, UserAchievement
from django.db import models
from django.db import transaction
from django.core.paginator import Paginator

class FriendRequestManagementView(APIView):
    
    def get_friendship_status(self, player_sender, player_receiver):
        return FriendInvitation.objects.filter(
            Q(player_sender=player_sender, player_receiver=player_receiver) |
            Q(player_sender=player_receiver, player_receiver=player_sender)
        ).first()
    
    def get(self, request, receiver_id):
        player_sender = request.user
        player_receiver = get_object_or_404(User, id=receiver_id)
        friend_invitation= self.get_friendship_status(player_sender, player_receiver)
        is_friend = Friendship.objects.filter(Q(player=player_sender, friend=player_receiver) | Q(player=player_receiver, friend=player_sender)).exists()
        if is_friend:
            return Response({'message': 'Friends'}, status=status.HTTP_200_OK)
        if friend_invitation:
            if friend_invitation.player_sender == player_sender:
                return Response({"message": "Friend request sent."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Friend request received."}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Friend request does not exist."}, status=status.HTTP_200_OK)
    
    def post(self, request, receiver_id):
        player_sender = request.user
        player_receiver = get_object_or_404(User, id=receiver_id)
        
        if self.get_friendship_status(player_sender, player_receiver):
            return Response({'error': 'Friend request already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            friend_request = FriendInvitation(player_sender=player_sender, player_receiver=player_receiver)
            friend_request.save()
            Notification.objects.create(
                recipient=player_receiver,
                sender=player_sender,
                message='sent you a friend request.'
            )

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{player_receiver.id}',
                {
                    'type': 'notification_message',
                    'message': f'{player_sender.username} sent you a friend request.'
                }
            )
            return Response({'message': 'Friend request sent successfully.'}, status=status.HTTP_201_CREATED)
        except:
            return Response({'error': "Some error happend"}, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, receiver_id):
        player_sender = request.user
        player_receiver = get_object_or_404(User, id=receiver_id)

        try:
            invitation = get_object_or_404(FriendInvitation, player_sender=player_sender, player_receiver=player_receiver)
            invitation.delete()
            return Response({'message': 'Friend request canceled.'}, status=status.HTTP_202_ACCEPTED)
        except FriendInvitation.DoesNotExist:
            return Response({'error': 'Friend request not found.'}, status=status.HTTP_400_BAD_REQUEST)
    

            
class FriendRequestResponse(APIView):
    def patch(self, request, sender_id):
        player_sender = get_object_or_404(User, id=sender_id)
        player_receiver = request.user
        friend_request = get_object_or_404(FriendInvitation, player_sender=player_sender, player_receiver=player_receiver)
        if friend_request.invite_status != 'P':
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
        action = request.data.get('status')
        if action not in ['accept', 'reject']:
            return Response({'error': 'Invalid action. Choose "accept" or "reject".'}, status=status.HTTP_400_BAD_REQUEST)
        if action == 'accept':
            friend_request.invite_status = 'A'
            friendship = Friendship(player=player_sender, friend=player_receiver)
            friendship.save()
            friend_request.delete()
            self.check_and_award_friends_achievement(player_sender, player_receiver)
            return Response({'message': 'Friend request accepted.'}, status=status.HTTP_200_OK)
        elif action == 'reject':
            friend_request.delete()
            return Response({'message': 'Friend request rejected.'}, status=status.HTTP_200_OK)
        
    def check_and_award_friends_achievement(self, player_sender, player_receiver):
        sender_friend_count = Friendship.objects.filter(player=player_sender).count() + Friendship.objects.filter(friend=player_sender).count()
        receiver_friend_count = Friendship.objects.filter(player=player_receiver).count() + Friendship.objects.filter(friend=player_receiver).count()
        
        if sender_friend_count >= 1:
            self.unlock_five_friends_achievement(player_sender)
        if receiver_friend_count >= 1:
            self.unlock_five_friends_achievement(player_receiver)
    
    def unlock_five_friends_achievement(self, user):
        achievement, _ = Achievement.objects.get_or_create(
            title="Social Butterfly",
            defaults={'description': "Have more than 5 friends."}
        )
        user_achievement_exists = UserAchievement.objects.filter(user=user, achievement=achievement).exists()
        if not user_achievement_exists:
            UserAchievement.objects.create(
                user=user,
                achievement=achievement,
                unlocked=True
            )
            Notification.objects.create(
                recipient=user,
                sender=user,
                message='You Got a new Achievment',
                title='Social Butterfly',
                description='Have more than 5 friends.',
            )
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{user.id}',
                {
                    'type': 'notification_message',
                    'message': 'Got a new Achievment'
                }
            )


class FriendManagementView(APIView):
    def get(self, request, friend_id):
        currentUser = request.user
        friend = get_object_or_404(User, id=friend_id)
        is_friend = Friendship.objects.filter(Q(player=currentUser, friend=friend) | Q(player=friend, friend=currentUser)).exists()
        if is_friend:
            return Response({"message": f"{friend} is a friend."}, status=status.HTTP_200_OK)
        else:
            return Response({"message": f"{friend} is not a friend."}, status=status.HTTP_404_NOT_FOUND)
        
    def delete(self, request, friend_id):
        currentUser = request.user
        friend = friend = get_object_or_404(User, id=friend_id)
        friendship = Friendship.objects.filter(Q(player=currentUser, friend=friend) | Q(player=friend, friend=currentUser))
        if friendship.exists():
            friendship.delete()
            return Response({"message": f"Successfully unfriended {friend}."}, status=status.HTTP_202_ACCEPTED)
        else:
            return Response({"error": "Friendship does not exist."}, status=status.HTTP_400_BAD_REQUEST)


class BlockUnblockView(APIView):
    def post(self, request, blocked_id):
        blocker = request.user
        blocked = get_object_or_404(User, id=blocked_id)
        if BlockedUsers.objects.filter(Q(blocker=blocker, blocked=blocked) | Q(blocker=blocked, blocked=blocker)).exists():
            return Response({'error': 'User is already blocked.'}, status=status.HTTP_400_BAD_REQUEST)
        blocking = BlockedUsers(blocker=blocker, blocked=blocked)
        blocking.save()
        Friendship.objects.filter(Q(player=blocker, friend=blocked) | Q(player=blocked, friend=blocker)).delete()
        FriendInvitation.objects.filter(
            Q(player_sender=blocker, player_receiver=blocked) | 
            Q(player_sender=blocked, player_receiver=blocker)
        ).delete()
        return Response({'message': 'User has been blocked successfully.'}, status=status.HTTP_201_CREATED)
    def delete(self, request, blocked_id):
        blocker = request.user
        blocked = get_object_or_404(User, id=blocked_id)
        blocking = BlockedUsers.objects.filter(Q(blocker=blocker, blocked=blocked) | Q(blocker=blocked, blocked=blocker))
        if blocking.exists():
            blocking.delete()
            return Response({'message': 'User has been unblocked successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "user is not blocked."}, status=status.HTTP_400_BAD_REQUEST)
    def get(self, request, blocked_id=None):
        blocker = request.user
        if blocked_id:
            blocked = get_object_or_404(User, id=blocked_id)
            #i edit this to check both ways if you blocked or blocked you
            is_blocked = BlockedUsers.objects.filter(Q(blocker=blocker, blocked=blocked) | Q(blocker=blocked, blocked=blocker)).exists()
            return Response({'is_blocked': is_blocked}, status=status.HTTP_200_OK)
        else:
            blocked_users = BlockedUsers.objects.filter(blocker=blocker).select_related('blocked')
            blocked_list = [{'id': user.blocked.id, 'username': user.blocked.username} for user in blocked_users]
            return Response( blocked_list, status=status.HTTP_200_OK)

        
class CurrentFriendsListView(generics.ListAPIView):
    serializer_class = FriendshipSerializer

    def get_queryset(self):
        return Friendship.objects.filter(player=self.request.user)

 
class PlayerView(APIView):
    def get(self, request):
        player_id = request.user.id
        player = get_object_or_404(Player, user_id=player_id)
        serializer = PlayerSerializer(player)
        return(Response(serializer.data, status=status.HTTP_200_OK))
    
class OtherPlayerView(APIView):
    def get(self, request, player_id=None, username=None):
        requesting_user = request.user

        try:
            if player_id:
                player = get_object_or_404(Player, user_id=player_id)
            elif username:
                user = get_object_or_404(User, username=username)
                player = get_object_or_404(Player, user=user)
            else:
                return Response({'error': 'Either player_id or username must be provided'}, status=status.HTTP_400_BAD_REQUEST)

            profile_user = player.user

            is_blocked = BlockedUsers.objects.filter(
                blocker=profile_user, 
                blocked=requesting_user
            ).exists()

            is_blocking = BlockedUsers.objects.filter(
                blocker=requesting_user, 
                blocked=profile_user
            ).exists()
        

            serializer = PlayerSerializer(player)
            response_data = serializer.data

            response_data['is_blocked'] = is_blocked
            response_data['is_blocking'] = is_blocking
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    

class GamePlayersView(APIView):
    def get(self, request, player_id):
        player = get_object_or_404(Player, user_id=player_id)
        serializer = PlayerSerializer(player)
        return(Response(serializer.data, status=status.HTTP_200_OK))


# test for search 
class SearchAPIView(APIView):
    def get(self, request, *args, **kwargs):
        query = request.query_params.get('q', '')
        current_user = request.user
        if query:
            results = User.objects.filter(
                username__startswith=query,
                is_staff=False,  
                is_superuser=False 
            ).exclude(id=current_user.id)[:10]
            serializer = CurrentUserSerializer(results, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"results": []}, status=status.HTTP_200_OK)


class NotificationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        notifications = Notification.objects.filter(recipient=user).order_by('-timestamp')
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        user = request.user
        Notification.objects.filter(recipient=user, is_read=False).update(is_read=True)
        return Response({"status": "success"}, status=200)

class ListFriendsView(APIView):
    def get(self, request, *args, **kwargs):
        current_user = request.user
        friendships = Friendship.objects.filter(Q(player=current_user, blocked=False) | Q(friend=current_user, blocked=False))
        friends = [friendship.friend if friendship.player == current_user else friendship.player for friendship in friendships]
        serializer = CurrentUserSerializer(friends, many=True)
        return Response(serializer.data)
    



class TournamentsManagementView(APIView):
    def get(self, request):
        #cuz it returns a query set 
        tournament = Tournament.objects.filter(tournament_participants=request.user).first()
        if tournament:
            serializer = TournamentSerializer(tournament)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # checki wach nrado empty object wla 404 f status code 
            return Response({}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = TournamentCreateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            invited_users = serializer.validated_data.pop('invitedUsers', [])
            tournament = Tournament.objects.create(tournament_creator=request.user, **serializer.validated_data)
            tournament.tournament_participants.add(self.request.user)
            for user_id in invited_users:
                user = get_object_or_404(User, id=user_id)
                TournamentInvitation.objects.create(tournament=tournament, player=user)
                Notification.objects.create(
                    recipient=user,
                    sender=request.user,
                    message='invited you to a tournament'
                )
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f'notifications_{user_id}',
                    {
                        'type': 'notification_message',
                        'message': 'you have been invited to a tournament'
                    }
                )
            return Response({'message': 'Tournament created successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        tournament = Tournament.objects.filter(tournament_creator=request.user).first()
        if tournament:
            tournament.delete()
            return Response({'message': 'Tournament deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Tournament not found.'}, status=status.HTTP_404_NOT_FOUND)
        

class TournamentInvitationView(APIView):
    def get(self, request):
        invitation = get_object_or_404(TournamentInvitation, player=request.user)
        serializer = TournamentInvitationSerializer(invitation)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, tournament_id):
        tournament = get_object_or_404(Tournament, id=tournament_id)
        player = request.user
        invitation = get_object_or_404(TournamentInvitation, tournament=tournament, player=player)
        action = request.data.get('status')
        if action not in ['accept', 'reject']:
            return Response({'error': 'Invalid action. Choose "accept" or "reject".'}, status=status.HTTP_400_BAD_REQUEST)
        if action == 'accept':
            tournament.tournament_participants.add(player)
            if tournament.tournament_participants.count() == 4:
                tournament.assign_opponent()
                tournament.tournament_status = True
                tournament.assign_tournament_stage()
                tournament.save()
            invitation.delete()
            return Response({'message': 'Invitation accepted.'}, status=status.HTTP_200_OK)
        elif action == 'reject':
            invitation.delete()
            return Response({'message': 'Invitation rejected.'}, status=status.HTTP_200_OK)

class TournamentInvitationResponse(APIView):
    def patch(self, request, tournament_id):
        print("TOURNAMENT INVITATION HANDLER")
        return(Response({'message': 'Tournament started successfully'}, status=status.HTTP_200_OK))

class StartTournamentView(APIView):
    def post(self, request):
        current_user = request.user
        tournament = Tournament.objects.filter(tournament_creator=request.user).first()
        tournament.start_tournament()
        return(Response({'message': 'Tournament started successfully'}, status=status.HTTP_200_OK))



class TournamentByStageView(APIView):
    def get(self, request, stage):
        stage_participants = TournamentParticipants.objects.filter(matchStage=stage)
        serilaizer = TournamentParticipantsSerializer(stage_participants, many=True)
        print(serilaizer.data)
        return Response(serilaizer.data,  status=status.HTTP_200_OK)
    
class MissedNotificationsAPIView(APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        missed_notifications = Notification.objects.filter(recipient=user, is_read=False)
        
        serializer = NotificationSerializer(missed_notifications, many=True)
        return Response({
            "hasNotification": missed_notifications.exists(),
            "notifications": serializer.data
        }, status=status.HTTP_200_OK)

class XPHistoryView(APIView):
    def get(self, request, format=None):
        player = request.user.player
        xp_history = XPHistory.objects.filter(player=player).order_by('date')
        data = {
            'labels': [entry.date.strftime('%Y-%m-%d') for entry in xp_history],
            'xp': [entry.xp for entry in xp_history]
        }
        return Response(data)

class LeaderboardView(APIView):
    def get(self, request):
        page = request.GET.get('page', 1) 
        limit = request.GET.get('limit', 20)

        try:
            page = int(page)
            limit = int(limit)
        except ValueError:
            return Response({'error': 'Invalid pagination parameters'}, status=status.HTTP_400_BAD_REQUEST)

        players = Player.objects.filter(
            user__is_staff=False,
            user__is_superuser=False
        ).annotate(
            rank_order=Case(
                When(rank='GOLD', then=Value(1)),
                When(rank='SILVER', then=Value(2)),
                When(rank='BRONZE', then=Value(3)),
                default=Value(4),
                output_field=IntegerField(),
            )
        ).order_by('rank_order', '-xp')
        
        paginator = Paginator(players, limit)
        
        try:
            paginated_players = paginator.page(page)
        except:
            return Response({'results': [], 'has_more': False}, status=status.HTTP_200_OK)
        
        serializer = PlayerSerializer(paginated_players, many=True)

        return Response({
            'results': serializer.data,
            'has_more': paginated_players.has_next() 
        }, status=status.HTTP_200_OK)



class GlobalStatsView(APIView):
    def get(self, request):

        player = get_object_or_404(Player, user=request.user)
        notifications = Notification.objects.filter(recipient=request.user).order_by('-timestamp')
        #youness checki chnahiya dik models.Q
        game_history = GameHistory.objects.filter(models.Q(winner_user_id=request.user.id) | models.Q(loser_user_id=request.user.id))
        friendships = Friendship.objects.filter(Q(player=request.user, blocked=False) | Q(friend=request.user, blocked=False))
        friends = [friendship.friend if friendship.player == request.user else friendship.player for friendship in friendships]
        achievements = UserAchievement.objects.filter(user=request.user)

        #here 3adna 2 anwa3 dyal tournament online / offiline 
        tournament = Tournament.objects.filter(tournament_participants=request.user).first()
        if tournament:
            tournament = TournamentSerializer(tournament).data
        else:
            currentLocalPlayer = LocalPlayer.objects.filter(username=request.user.username).first()
            if currentLocalPlayer:
                tournament = currentLocalPlayer.tournament
                if tournament:
                    tournament = LocalTournamentSerializer(tournament).data
                else:
                    tournament = []
            else:
                tournament = []


        blocked_users = BlockedUsers.objects.filter(blocker=request.user).select_related('blocked')
        blocked_list = [{'id': user.blocked.id, 'username': user.blocked.username} for user in blocked_users]

        data = {
            'player_stats' : PlayerSerializer(player).data,
            'friends': CurrentUserSerializer(friends, many=True).data,
            'notifications': NotificationSerializer(notifications, many=True).data,
            'game_history': GameHistorySerializer(game_history, many=True).data,
            'achievements': UserAchievementSerializer(achievements, many=True).data,
            'tournament': tournament,
            'blocked_users': blocked_list
        }
        return(Response(data, status=status.HTTP_200_OK))




class LocalTournamentView(APIView):
    def get(self, request):
        #here we should also the tournament he is participating on 
        # currentLocalPlayer = LocalPlayer.objects.filter(username=request.user.username).first()
        # print(currentLocalPlayer)
        try : 
            currentLocalPlayer = LocalPlayer.objects.get(username=request.user.username)
        except LocalPlayer.DoesNotExist:
            return Response({}, status=status.HTTP_404_NOT_FOUND)
        tournament = currentLocalPlayer.tournament
        if tournament:
            serializer = LocalTournamentSerializer(tournament)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)



    def post(self, request):
        serializer = LocalTournamentCreatSerializer(data=request.data, context={'request': request})
        user = request.user
        if serializer.is_valid():
            invited_users = serializer.validated_data.pop('invitedUsers', [])
            tournament = LocalTournament.objects.create(tournament_creator=request.user, **serializer.validated_data)
            currentUserLocal = LocalPlayer.objects.create(tournament=tournament ,username=user.username)
            # tournament.tournament_participants.add(currentUserLocal)
            participants_list = [currentUserLocal]
            for participant in invited_users:
                participant = LocalPlayer.objects.create(tournament=tournament,username=participant)
                participants_list.append(participant)
                # tournament.tournament_participants.add(participant)
            tournament.assign_opponent(participants_list)

            return Response({'message': 'Tournament created successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request):
        tournament = get_object_or_404(LocalTournament, tournament_creator=request.user)
        print(tournament)
        if tournament:
            tournament.delete()
            return Response({'message': 'Tournament deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Tournament not found.'}, status=status.HTTP_404_NOT_FOUND)




class LocalPlayerCreateView(APIView):
    def post(self, request, format=None):
        username = request.data.get('username')
        paddle = request.data.get('paddle')
        keys = request.data.get('keys')
        print(f"{paddle, keys}")

        if not username:
            return Response({'error': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)

        player = LocalPlayer.objects.create(
            username=username,
            paddle_color=paddle,
            keys=keys
        )
        serializer = LocalPlayerSerializer(player)
        print(f"Created player: {serializer.data}")
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    def get(self, request, player_id, format=None):
        player = get_object_or_404(LocalPlayer, id=player_id)
        serializer = LocalPlayerSerializer(player)
        return Response(serializer.data)


class LocalTournamentParticipantsView(APIView):
    def get(self, request, stage):
        if stage not in ["FINALS", "SEMI-FINALS", "FINISHED"]:
            return {"Message": "Bad Request"}, status.HTTP_400_BAD_REQUEST
        currentLocalPlayer = LocalPlayer.objects.filter(username=request.user.username).first()
        tournament = currentLocalPlayer.tournament
        finals_participants = LocalTournamanetParticipants.objects.filter(tournament=tournament, matchStage="FINALS")
        semi_finals_participants = LocalTournamanetParticipants.objects.filter(tournament=tournament, matchStage="SEMI-FINALS")
        data = {
            'final' : LocalTournamentParticipantsSerializer(finals_participants, many=True).data,
            'semiFinal' : LocalTournamentParticipantsSerializer(semi_finals_participants, many=True).data,
        }
        return Response(data,  status=status.HTTP_200_OK)

class LocalTournamentParticipantResultView(APIView):
    def post(self, request):
        match_id = request.data.get('tournamentId');
        winner = request.data.get('winner');
        loser = request.data.get('loser');
        match = get_object_or_404(LocalTournamanetParticipants, id=match_id)
        winner_obj = get_object_or_404(LocalPlayer, username=winner)
        loser_obj = get_object_or_404(LocalPlayer, username=loser)
        print(f"{winner, loser}")
        with transaction.atomic():
            match.winner = winner_obj
            match.loosers = loser_obj
            match.matchPlayed = True
            match.save()
        match.tournament.assign_tournament_stage()
        return Response("MATCH ID RECEIVED")

# to do list:
# zid paddle keys avatar random
