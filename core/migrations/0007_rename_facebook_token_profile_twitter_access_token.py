# Generated by Django 5.1.2 on 2025-07-01 10:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_alter_profile_bio_alter_profile_facebook_token_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='facebook_token',
            new_name='twitter_access_token',
        ),
    ]
