from django.db import models
from django.conf import settings
from datetime import date
# Create your models here.
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
import random
from  .achievement_service import AchievementService
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def user_avatar_upload_path(instance, filename):
    return f"player/{instance.id}/user_avatar/{filename}"

class XPHistory(models.Model):
    player = models.ForeignKey('Player', on_delete=models.CASCADE, related_name='xp_history')
    xp = models.IntegerField()
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.player.user.username} - {self.xp} XP on {self.date}"

class Player(models.Model):
    PLAYER_RANK_BRONZE = 'BRONZE'
    PLAYER_RANK_SILVER = 'SILVER'
    PLAYER_RANK_GOLD = 'GOLD'
    PLAYER_FIRST_RANK_PROGRESS = 0
    PLAYER_FIRST_GAMES_PLAYED = 0
    PLAYER_FIRST_GAMES_WON = 0
    PLAYER_FIRST_GAMES_XP = 0

    RANK_XP_THRESHOLDS = {
        PLAYER_RANK_BRONZE: 1000,
        PLAYER_RANK_SILVER: 2000,
        PLAYER_RANK_GOLD: 3000,
    }
    
    RANK_ORDER = [PLAYER_RANK_BRONZE, PLAYER_RANK_SILVER, PLAYER_RANK_GOLD]
    
    rank = models.CharField(max_length=15, default=PLAYER_RANK_BRONZE)
    rank_progress = models.DecimalField(max_digits=5, decimal_places=2, default=PLAYER_FIRST_RANK_PROGRESS)
    games_played = models.IntegerField(default=PLAYER_FIRST_GAMES_PLAYED)
    games_won = models.IntegerField(default=PLAYER_FIRST_GAMES_WON)
    xp = models.IntegerField(default=PLAYER_FIRST_GAMES_XP)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)

    def __str__(self) -> str:
        return self.user.username


    def get_rank_progress(self):
        if self.rank == self.PLAYER_RANK_BRONZE:
            return (self.xp / self.RANK_XP_THRESHOLDS[self.PLAYER_RANK_BRONZE]) * 100
        elif self.rank == self.PLAYER_RANK_SILVER:
            return (self.xp / self.RANK_XP_THRESHOLDS[self.PLAYER_RANK_SILVER]) * 100
        elif self.rank == self.PLAYER_RANK_GOLD:
            return (self.xp / self.RANK_XP_THRESHOLDS[self.PLAYER_RANK_GOLD]) * 100

    def update_xp(self, won: bool):
        print(f"Before: {self.xp}")
        if won:
            self.xp += 50
            self.games_won += 1
            AchievementService.check_and_award_ten_wins_achievement(self)
            print(f"{self.user.username} +50XP")
        else:
            self.xp -= 20
            self.xp = max(0, self.xp)
            print(f"{self.user.username} -20XP")
        print(f"After: {self.xp}")

        self.games_played += 1
        AchievementService.check_and_award_first_game_achievement(self)
        current_rank_index = self.RANK_ORDER.index(self.rank)
        max_xp_for_current_rank = self.RANK_XP_THRESHOLDS[self.rank]
        
        if self.xp >= max_xp_for_current_rank and current_rank_index < len(self.RANK_ORDER) - 1:
            self.rank = self.RANK_ORDER[current_rank_index + 1]
            self.xp = 0 
        
        XPHistory.objects.update_or_create(
            player=self,
            date=date.today(),
            defaults={'xp': self.xp}
        )
        self.save()


class FriendInvitation(models.Model):
    INVITATION_CHOICES = [
        ('A', 'ACCEPTED'),
        ('P', 'PENDING'),
        ('D', 'DECLINED')
    ]
    player_sender = models.ForeignKey(settings.AUTH_USER_MODEL,related_name='sent_invitations', on_delete=models.CASCADE)
    player_receiver = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='receive_invitations',on_delete=models.CASCADE)
    invite_status = models.CharField(max_length=1,choices=INVITATION_CHOICES, default='P')
    send_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["player_sender", "player_receiver"]

    def __str__(self) -> str:
        return f"invitation from {self.player_sender.username} to {self.player_receiver.username} - status : {self.invite_status}"
    
    def save(self, *args, **kwargs):
        if self.player_sender == self.player_receiver:
            raise ValidationError("A Player cannot send an invitation to themselves")
        super().save(*args, **kwargs)



class Notification(models.Model):
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_notifications')
    message = models.TextField()
    title = models.TextField(default='No description provided')
    description = models.TextField(default='No description provided')
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f'Notification from {self.sender} to {self.recipient}'

class Friendship(models.Model):
    player = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='friendships', on_delete=models.CASCADE)
    friend = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='friends_with', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    blocked = models.BooleanField(default=False)

    class Meta:
        unique_together = ('player', 'friend')

    def __str__(self) -> str:
        return f"{self.player.username} is friends with {self.friend.username}"

    def clean(self):
        if self.player == self.friend:
            raise ValidationError("A player cannot be friends with themselves.")
        
    # def save(self, *args, **kwargs):
    #     super().save(*args, **kwargs)
    #     if not Friendship.objects.filter(player=self.friend, friend=self.player).exists():
    #         Friendship.objects.create(player=self.friend, friend=self.player)

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        Friendship.objects.filter(player=self.friend, friend=self.player).delete()

    def __str__(self):
        return f"{self.player.username} is friends with {self.friend.username}"
    

class BlockedUsers(models.Model):
    blocker = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='blocker_user', on_delete=models.CASCADE)
    blocked = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='blocked_user', on_delete=models.CASCADE)
    blocked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')

    def __str__(self):
        return f"{self.blocker} blocked {self.blocked}"


#this to organize who is gonna play aginst who
#the nullable field jus temp 
class TournamentParticipants(models.Model):
    tournament = models.ForeignKey('Tournament', on_delete=models.CASCADE)  # Use a string reference here
    player1 = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='player1', null=True, blank=True)
    player2 = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='player2', null=True, blank=True)
    matchPlayed = models.BooleanField(default=False)
    matchStage = models.CharField(max_length=100, default="SEMI-FINALS")
    winner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='winner', null=True, blank=True)
    loosers = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='loosers', null=True, blank=True)

    def assign_winner(self, winner, looser):
        self.loosers = looser
        self.winner = winner
        self.matchPlayed = True
        #remove tghe looser player from the tournament
        if self.player1 == winner:
            self.player2.tournament_participants.remove(self.tournament)
        else:
            self.player1.tournament_participants.remove(self.tournament)
        self.save()

    def notify_players(self, tournament_creator):
        Notification.objects.create (
            recipient=self.player1,
            sender=tournament_creator,
            message='has challenged you to a game!'
        )
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
        f'notifications_{self.player1.id}',
            {
                'type': 'notification_tournament',
                'message': f'{tournament_creator} has invited you to play a game.',
                'sender': tournament_creator.id, 
            }
        )

        Notification.objects.create (
            recipient=self.player2,
            sender=tournament_creator,
            message='has challenged you to a game!'
        )
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
        f'notifications_{self.player2.id}',
            {
                'type': 'notification_tournament',
                'message': f'{tournament_creator} has invited you to play a game.',
                'sender': tournament_creator.id, 
            }
        )

    def __str__(self):  
        return f"{self.player1} vs {self.player2} in {self.tournament}"


class Tournament(models.Model):
    tournament_creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    tournament_name = models.CharField(max_length=100)
    tournament_prize = models.IntegerField(default=0) # khas n3amerha 3la 7ssab kola user dert haka gha for testing
    tournament_map = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True) 
    tournament_date = models.DateTimeField(auto_now_add=True) # hadi f ina date tournament hadi khasha t3awerd
    tournament_status = models.BooleanField(default=False) # hadi ghadi tbadelha b True lma ykono les places kamline
    tournament_stage = models.CharField(max_length=100, default="semi-finals") # hadi f ina stage wasla tournament
    is_online = models.BooleanField(default=True)

    tournament_participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='tournament_participants')
   
    def assign_tournament_prize(self):
        print(self.tournament_creator.player.rank)
        if self.tournament_creator.player.rank == 'BRONZE':
            self.tournament_prize = 2000
        elif self.tournament_creator.player.rank == 'SILVER':
            self.tournament_prize = 4000
        elif self.tournament_creator.player.rank == 'GOLD':
            self.tournament_prize = 6000

    
    def assign_opponent(self):
        from game.models import TournamentGameRoom
        participants = list(self.tournament_participants.all())
        random.shuffle(participants)
        for i in range(0, len(participants), 2):
            TournamentParticipants.objects.create(tournament=self, player1=participants[i], player2=participants[i+1])
            TournamentGameRoom.objects.create(player1=participants[i].player, player2=participants[i+1].player)


    def assign_tournament_stage(self):
        if self.tournament_participants.count() == 4:
            self.tournament_stage = 'SEMI-FINALS'
        elif self.tournament_participants.count() == 2:
            self.tournament_stage = 'FINALS'
        else:
            self.tournament_stage = 'GROUP-STAGE'
    
    def start_tournament(self):
        tournamentParticipants = TournamentParticipants.objects.filter(tournament=self)
        for participant in tournamentParticipants:
            participant.notify_players(self.tournament_creator)


    def save(self, *args, **kwargs):
        self.assign_tournament_prize()
        super().save(*args, **kwargs)
    def __str__(self):
        return self.tournament_name


class TournamentInvitation(models.Model):
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    player = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    invitation_status = models.BooleanField(default=False)
    invitation_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.player} invited to {self.tournament}"


    
# class LocalTournamentUser(models.Model):
#     tournament = models.ForeignKey('LocalTournament', related_name='participants', on_delete=models.CASCADE)
#     username = models.CharField(max_length=100)
#     avatar = models.ImageField(upload_to=user_avatar_upload_path)

#     def __str__(self):
#         return self.username


class LocalPlayer(models.Model):

    username = models.CharField(max_length=100)
    avatar = models.ImageField(null=True, blank=True)
    paddle_color = models.CharField(max_length=7, null=True, blank=True)
    keys = models.JSONField(null=True, blank=True)
    # i want to add a field for the tournament if the player is a prt of tournament if not i want it to be null
    tournament = models.ForeignKey('LocalTournament', related_name='participants', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.username



class LocalTournament(models.Model):
    tournament_creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    tournament_name = models.CharField(max_length=100)
    tournament_map = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    tournament_status = models.BooleanField(default=False)
    tournament_stage = models.CharField(max_length=100, default="SEMI-FINALS")
    is_online = models.BooleanField(default=False)

    def __str__(self):
        return self.tournament_name

    def assign_opponent(self, participants_list):
        # random.shuffle(participants)
        for i in range(0, len(participants_list), 2):
            LocalTournamanetParticipants.objects.create(tournament=self, player1=participants_list[i], player2=participants_list[i+1])
            # TournamentGameRoom.objects.create(ç=participants[i], player2=participants[i+1])
    def assign_tournament_stage(self):
        print("HELLO FROM TOURNAMENT STAGE")
        # participants = LocalTournamanetParticipants.objects.filter(tournament=self)
        #the tournament created by default on semi-finals with 2 object of participant 2 players each so we have to check if the tournament is a Semi final after that we check the match played if both maches are played we change the stage to finals
        # we creat the final match participants the both matches are played 
        if self.tournament_stage == 'SEMI-FINALS':
            participants = LocalTournamanetParticipants.objects.filter(tournament=self, matchStage='SEMI-FINALS')
            if participants[0].matchPlayed and participants[1].matchPlayed:
                winner1 = participants[0].winner
                winner2 = participants[1].winner
                LocalTournamanetParticipants.objects.create(tournament=self, player1=winner1, player2=winner2, matchStage="FINALS")
                self.tournament_stage = 'FINALS'
                self.save()
        elif self.tournament_stage == 'FINALS':
            participants = LocalTournamanetParticipants.objects.filter(tournament=self, matchStage='FINALS')
            if participants[0].matchPlayed:
                self.tournament_stage = 'FINISHED'
                self.save()
                
class LocalTournamanetParticipants(models.Model):
    tournament = models.ForeignKey(LocalTournament, on_delete=models.CASCADE)
    player1 = models.ForeignKey(LocalPlayer, on_delete=models.CASCADE, related_name='local_player1')
    player2 = models.ForeignKey(LocalPlayer, on_delete=models.CASCADE, related_name='local_player2')
    matchPlayed = models.BooleanField(default=False)
    matchStage = models.CharField(max_length=100, default="SEMI-FINALS")
    winner = models.ForeignKey(LocalPlayer, on_delete=models.CASCADE, related_name='local_winner', null=True, blank=True)
    loosers = models.ForeignKey(LocalPlayer, on_delete=models.CASCADE, related_name='local_loosers' , null=True, blank=True)

    def __str__(self):
        return f"{self.player1} vs {self.player2} in {self.tournament}"