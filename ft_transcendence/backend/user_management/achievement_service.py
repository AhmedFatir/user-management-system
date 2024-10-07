from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer



class AchievementService:
    @staticmethod
    def check_and_award_first_game_achievement(player):
        if player.games_played == 1:
            AchievementService.unlock_first_game_achievement(player)

    @staticmethod
    def unlock_first_game_achievement(player):
        from game.models import Achievement, UserAchievement
        from user_management.models import Notification

        achievement, _ = Achievement.objects.get_or_create(
            title="First Game",
            defaults={'description': "Complete your first game of Ping Pong."}
        )
        user_achievement_exists = UserAchievement.objects.filter(user=player.user, achievement=achievement).exists()
        if not user_achievement_exists:
            UserAchievement.objects.create(
                user=player.user,
                achievement=achievement,
                unlocked=True
            )
            Notification.objects.create(
                recipient=player.user,
                sender=player.user,
                message='You Got a new Achievment',
                title='First Game',
                description='Complete your first game of Ping Pong.',
            )
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{player.user.id}',
                {
                    'type': 'notification_message',
                    'message': 'Got a new Achievment'
                }
            )

    @staticmethod
    def check_and_award_ten_wins_achievement(player):
        from game.models import Achievement, UserAchievement 
        from user_management.models import Notification  

        if player.games_won >= 2:
            AchievementService.unlock_ten_wins_achievement(player)

    @staticmethod
    def unlock_ten_wins_achievement(player):
        from game.models import Achievement, UserAchievement  
        from user_management.models import Notification 

        achievement, _ = Achievement.objects.get_or_create(
            title="Ping Pong Prodigy",
            defaults={'description': "Win 10 games of Ping Pong."}
        )
        user_achievement_exists = UserAchievement.objects.filter(user=player.user, achievement=achievement).exists()
        if not user_achievement_exists:
            UserAchievement.objects.create(
                user=player.user,
                achievement=achievement,
                unlocked=True
            )
            Notification.objects.create(
                recipient=player.user,
                sender=player.user,
                message='You Got a new Achievment',
                title='Ping Pong Prodigy',
                description='Win 10 games of Ping Pong.',
            )
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{player.user.id}',
                {
                    'type': 'notification_message',
                    'message': 'Got a new Achievment'
                }
            )
