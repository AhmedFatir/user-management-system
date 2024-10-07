from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from user_management.models import Player, LocalPlayer
from authentication.models import User

def achievement_image_upload_path(instance, filename):
    return f"Achievments/{filename}"

class GameHistory(models.Model):
    GAME_TYPES = [
        ('pingpong', 'Ping Pong'),
        ('xo', 'XO'),
    ]
    
    MATCH_TYPES = [
        ('single', 'Single Match'),
        ('tournament', 'Tournament Match'),
    ]
    
    winner_user = models.ForeignKey(
        Player,
        related_name='won_games',
        on_delete=models.CASCADE
    )
    loser_user = models.ForeignKey(
        Player,
        related_name='lost_games',
        on_delete=models.CASCADE
    )
    winner_score = models.IntegerField()
    loser_score = models.IntegerField()
    game_type = models.CharField(max_length=20, choices=GAME_TYPES)
    match_type = models.CharField(max_length=20, choices=MATCH_TYPES)
    played_at = models.DateTimeField(auto_now_add=True)
    
    # def clean(self):
    #     if self.winner_user == self.loser_user:
    #         raise ValidationError("A player cannot play a game against themselves.")
        
    def __str__(self):
        return f"{self.winner_user} vs {self.loser_user}"

class Achievement(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    image = models.ImageField(upload_to=achievement_image_upload_path)
    task = models.TextField()

    def __str__(self):
        return self.title

class UserAchievement(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    achievement = models.ForeignKey(Achievement, on_delete=models.CASCADE)
    unlocked = models.BooleanField(default=False)
    achieved_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.achievement.title}"

class GameSettings(models.Model):
    user = models.ForeignKey(Player, on_delete=models.CASCADE, blank=True, null=True)
    background = models.CharField(max_length=255)
    paddle = models.CharField(max_length=255)
    keys = models.CharField(max_length=255)
    gameMode = models.CharField(max_length=255)
    def __str__(self):
        return f"{self.background} {self.paddle} {self.gameMode}"

class GameRoom(models.Model):
    player1 = models.ForeignKey(Player, related_name='player1', on_delete=models.CASCADE, null=True, blank=True)
    player2 = models.ForeignKey(Player, related_name='player2', on_delete=models.CASCADE, null=True, blank=True)
    is_waiting = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    player1_disconnected_at = models.DateTimeField(null=True, blank=True)
    player2_disconnected_at = models.DateTimeField(null=True, blank=True)
    player1_reconnected = models.BooleanField(default=False)
    player2_reconnected = models.BooleanField(default=False)
    
    def add_player(self, player):
        if not self.player1:
            self.player1 = player
        elif not self.player2:
            self.player2 = player
        else:
            raise ValueError("Room is already full")
        if self.player1 and self.player2:
            self.is_waiting = False
        self.save()

    def get_players(self):
        return self.player1, self.player2

    def leave_room(self, player):
        if self.player1 == player:
            self.player1 = None
        elif self.player2 == player:
            self.player2 = None
        
        if not self.player1 and not self.player2:
            self.delete()
        else:
            self.save()

class InviteGameRoom(models.Model):
    player1 = models.ForeignKey(Player, related_name='invited1', on_delete=models.CASCADE, null=True, blank=True)
    player2 = models.ForeignKey(Player, related_name='invited2', on_delete=models.CASCADE, null=True, blank=True)
    is_waiting = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    player1_connected = models.BooleanField(default=False)
    player2_connected = models.BooleanField(default=False)

    def set_player_connected(self, player):
        print(f"{self.player1_connected, self.player2_connected} ++++++++++++++++++++++++++++")
        if self.player1 == player:
            self.player1_connected = True
            print("player1 connected")
        elif self.player2 == player:
            self.player2_connected = True
            print("player2 connected")
        self.save()
        print(f"{self.player1_connected, self.player2_connected} ++++++++++++++++++++++++++++")


    def check_and_update_status(self):
        if self.player1_connected and self.player2_connected:
            self.is_waiting = False
            print("Both players are connected, game is ready to start.")
            self.save()
        
    def add_player(self, player):
        if not self.player1:
            self.player1 = player
        elif not self.player2:
            self.player2 = player
        else:
            raise ValueError("Room is already full")
        if self.player1 and self.player2:
            self.is_waiting = False
        self.save()

    def get_players(self):
        return self.player1, self.player2

    def leave_room(self, player):
        if self.player1 == player:
            self.player1 = None
        elif self.player2 == player:
            self.player2 = None
        
        if not self.player1 and not self.player2:
            self.delete()
        else:
            self.save()
        
class GameChallenge(models.Model):
    INVITATION_CHOICES = [
        ('A', 'ACCEPTED'),
        ('P', 'PENDING'),
        ('D', 'DECLINED')
    ]
    player_sender = models.ForeignKey(settings.AUTH_USER_MODEL,related_name='sender', on_delete=models.CASCADE)
    player_receiver = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='receiver',on_delete=models.CASCADE)
    status = models.CharField(max_length=1,choices=INVITATION_CHOICES, default='P')
    send_at = models.DateTimeField(auto_now_add=True)
    invite_game_room = models.OneToOneField(InviteGameRoom, on_delete=models.CASCADE, null=True, blank=True)
    class Meta:
        unique_together = ["player_sender", "player_receiver"]

    def __str__(self) -> str:
        return f"invitation from {self.player_sender.username} to {self.player_receiver.username} - status : {self.invite_status}"



class TournamentGameRoom(models.Model):
    player1 = models.ForeignKey(Player, related_name='tournament_player1', on_delete=models.CASCADE, null=True, blank=True)
    player2 = models.ForeignKey(Player, related_name='tournament_player2', on_delete=models.CASCADE, null=True, blank=True)
    is_waiting = models.BooleanField(default=True)
    crateated_at = models.DateTimeField(auto_now_add=True)
    player1_connected = models.BooleanField(default=False)
    player2_connected = models.BooleanField(default=False)

    def set_player_connected(self, player):
        if self.player1 == player:
            self.player1_connected = True
            print("player1 connected")
        elif self.player2 == player:
            self.player2_connected = True
            print("player2 connected")
        self.save()
    
    def check_and_update_status(self):
        if self.player1_connected and self.player2_connected:
            self.is_waiting = False
            self.save()




class LocalGameRoom(models.Model):
    player1 = models.ForeignKey(LocalPlayer, related_name='local_game_room_player1', on_delete=models.CASCADE, null=True, blank=True)
    player2 = models.ForeignKey(LocalPlayer, related_name='local_game_room_player2', on_delete=models.CASCADE, null=True, blank=True)
    arena = models.CharField(max_length=100)
    crateated_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return "__Local_Game_Room"