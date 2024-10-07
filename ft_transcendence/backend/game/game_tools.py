from asgiref.sync import sync_to_async

@sync_to_async
def get_player(user):
    from user_management.models import Player
    try:
        player, created = Player.objects.get_or_create(user_id=user)
        if created:
            print(f"Player created with id {user.id}")
    except:
        print("Error getting player")
    return player

@sync_to_async
def find_or_create_room(user):
    from user_management.models import Player
    from .models import GameRoom
    print(f"{user.id}")
    try:
        player, created = Player.objects.get_or_create(user_id=user)
        print(f"{player, user.id}")
        room = GameRoom.objects.filter(is_waiting=True).first()
        print(f"{room}")
        if room:
            room.player2 = player
            room.is_waiting = False
            room.save()
            print("Room updated with player2")
        else:
            room = GameRoom.objects.create(player1=player, is_waiting=True)
            print("hello world")
            print("New room created")
        return room
    except Exception as e:
        print(f"Error finding or creating room: {e}")
        raise

