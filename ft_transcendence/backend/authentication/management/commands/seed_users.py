from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
from faker import Faker
import random
from datetime import datetime

from user_management.models import Friendship, FriendInvitation, Notification, BlockedUsers 
from game.models import GameHistory, Achievement, UserAchievement, Player  # Import your models

class Command(BaseCommand):
    help = 'Seed the database with fake user data, friend invitations, notifications, blocked users, game history, and achievements'

    def add_arguments(self, parser):
        parser.add_argument(
            '--num',
            type=int,
            default=40,
            help='Number of users to create'
        )
        parser.add_argument(
            '--games',
            type=int,
            default=50,
            help='Number of game history entries to create'
        )
        parser.add_argument(
            '--achievements',
            type=int,
            default=10,
            help='Number of global achievements to create'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        fake = Faker()
        User = get_user_model()
        num_users = options['num']
        num_games = options['games']
        num_achievements = options['achievements']
        avatar_options = [f'avatars/{i}.png' for i in range(4)]

        # Create users and corresponding players
        users = []
        for _ in range(num_users):
            user = User(
                username=fake.user_name(),
                email=fake.email(),
                avatar=random.choice(avatar_options),
                api_42_id=None,  # Set api_42_id to None
                is_online=fake.boolean()
            )
            user.set_password('Team@123')  # Set a random password
            user.save()  # Save the user, which will automatically create a Player instance
            users.append(user)
            self.stdout.write(self.style.SUCCESS(f'Successfully created user {user.username} with avatar {user.avatar}'))

        # Create blocked users
        for user in users:
            potential_blocked_users = [u for u in users if u != user]
            blocked_users = random.sample(potential_blocked_users, min(len(potential_blocked_users), random.randint(1, 5)))
            for blocked_user in blocked_users:
                if not BlockedUsers.objects.filter(blocker=user, blocked=blocked_user).exists():
                    BlockedUsers.objects.create(blocker=user, blocked=blocked_user)
                    self.stdout.write(self.style.SUCCESS(f'{user.username} blocked {blocked_user.username}'))

        # Create friend invitations and notifications
        for user in users:
            potential_friends = [u for u in users if u != user and not BlockedUsers.objects.filter(blocker=user, blocked=u).exists()]
            for potential_friend in random.sample(potential_friends, min(len(potential_friends), random.randint(1, 5))):
                if not FriendInvitation.objects.filter(player_sender=user, player_receiver=potential_friend).exists():
                    invite_status = random.choice(['P', 'A'])  # Randomly choose status: PENDING or ACCEPTED
                    invitation = FriendInvitation.objects.create(
                        player_sender=user,
                        player_receiver=potential_friend,
                        invite_status=invite_status
                    )
                    self.stdout.write(self.style.SUCCESS(f'Sent invitation from {user.username} to {potential_friend.username} with status {invite_status}'))

                    # Create a notification for the recipient
                    Notification.objects.create(
                        recipient=potential_friend,
                        sender=user,
                        message=f'{user.username} sent you a friend invitation.',
                        is_read=False
                    )
                    self.stdout.write(self.style.SUCCESS(f'Notification created for {potential_friend.username} from {user.username}'))

        # Convert accepted invitations into friendships
        for invitation in FriendInvitation.objects.filter(invite_status='A'):
            if not Friendship.objects.filter(player=invitation.player_sender, friend=invitation.player_receiver).exists():
                Friendship.objects.create(player=invitation.player_sender, friend=invitation.player_receiver)
                self.stdout.write(self.style.SUCCESS(f'Created friendship: {invitation.player_sender.username} - {invitation.player_receiver.username}'))

            # Ensure reciprocal friendship
            if not Friendship.objects.filter(player=invitation.player_receiver, friend=invitation.player_sender).exists():
                Friendship.objects.create(player=invitation.player_receiver, friend=invitation.player_sender)
                self.stdout.write(self.style.SUCCESS(f'Created reciprocal friendship: {invitation.player_receiver.username} - {invitation.player_sender.username}'))

        # Create game history entries
        for _ in range(num_games):
            winner, loser = random.sample(users, 2)
            winner_player = winner.player
            loser_player = loser.player
            game_type = random.choice(['pingpong', 'xo'])
            match_type = random.choice(['single', 'tournament'])
            winner_score = random.randint(1, 10)
            loser_score = random.randint(1, 10)
            if winner_score == loser_score:
                winner_score += 1  # Ensure there's a winner and loser
            
            GameHistory.objects.create(
                winner_user=winner_player,
                loser_user=loser_player,
                winner_score=winner_score,
                loser_score=loser_score,
                game_type=game_type,
                match_type=match_type,
                played_at=fake.date_time_this_year()
            )
            self.stdout.write(self.style.SUCCESS(f'Created game history: {winner.username} vs {loser.username} ({game_type}, {match_type})'))

        # Create global achievements
        achievements = []
        for i in range(num_achievements):
            achievement = Achievement.objects.create(
                title=f'Achievement {i+1}',
                description=f'Description for achievement {i+1}',
                image=f'achievements/{i}.png',
                task=f'Task for achievement {i+1}'
            )
            achievements.append(achievement)
            self.stdout.write(self.style.SUCCESS(f'Created achievement: {achievement.title}'))

        # Assign achievements to users
        for user in users:
            user_achievements = random.sample(achievements, min(len(achievements), random.randint(1, 5)))
            for achievement in user_achievements:
                if not UserAchievement.objects.filter(user=user, achievement=achievement).exists():
                    UserAchievement.objects.create(user=user, achievement=achievement, unlocked=random.choice([True, False]))
                    self.stdout.write(self.style.SUCCESS(f'Assigned achievement {achievement.title} to user {user.username}'))
