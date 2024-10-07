# Generated by Django 4.2.13 on 2024-09-23 12:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_management', '0007_localtournamanetparticipants'),
    ]

    operations = [
        migrations.AlterField(
            model_name='localtournamanetparticipants',
            name='loosers',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='local_loosers', to='user_management.localtournamentuser'),
        ),
        migrations.AlterField(
            model_name='localtournamanetparticipants',
            name='winner',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='local_winner', to='user_management.localtournamentuser'),
        ),
    ]