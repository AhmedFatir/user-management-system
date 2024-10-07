# Generated by Django 4.2.13 on 2024-09-23 12:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_management', '0006_remove_localtournament_tournament_participants_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='LocalTournamanetParticipants',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('matchPlayed', models.BooleanField(default=False)),
                ('matchStage', models.CharField(default='SEMI-FINALS', max_length=100)),
                ('loosers', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='local_loosers', to='user_management.localtournamentuser')),
                ('player1', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='local_player1', to='user_management.localtournamentuser')),
                ('player2', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='local_player2', to='user_management.localtournamentuser')),
                ('tournament', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user_management.localtournament')),
                ('winner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='local_winner', to='user_management.localtournamentuser')),
            ],
        ),
    ]
