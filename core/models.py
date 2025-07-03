from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_pic = models.ImageField(upload_to='profile_pics/', default='default-profile.png', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)

    linkedin_token = models.CharField(max_length=512, blank=True, null=True)

    # Twitter Integration Fields
    twitter_access_token = models.CharField(max_length=512, blank=True, null=True)
    twitter_refresh_token = models.CharField(max_length=512, blank=True, null=True)
    twitter_token_updated_at = models.DateTimeField(blank=True, null=True)
    twitter_user_id = models.CharField(max_length=255, blank=True, null=True)
    twitter_username = models.CharField(max_length=255, blank=True, null=True)

    # Reddit Integration Fields
    reddit_access_token = models.CharField(max_length=512, blank=True, null=True)
    reddit_refresh_token = models.CharField(max_length=512, blank=True, null=True)
    reddit_username = models.CharField(max_length=255, blank=True, null=True)
    reddit_token_updated_at = models.DateTimeField(blank=True, null=True)

    # YouTube Integration Fields
    youtube_token = models.CharField(max_length=512, blank=True, null=True)
    youtube_refresh_token = models.CharField(max_length=512, blank=True, null=True)
    youtube_channel_id = models.CharField(max_length=255, blank=True, null=True)
    youtube_channel_name = models.CharField(max_length=255, blank=True, null=True)
    youtube_subscribers = models.PositiveIntegerField(blank=True, null=True)
    youtube_views = models.PositiveIntegerField(blank=True, null=True)
    youtube_videos = models.PositiveIntegerField(blank=True, null=True)
    youtube_token_updated_at = models.DateTimeField(blank=True, null=True)

    # OTP & Verification Fields
    otp_code = models.CharField(max_length=10, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    otp_temp_phone = models.CharField(max_length=15, blank=True, null=True)

    unverified_email = models.EmailField(blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Profile"

    def is_linkedin_linked(self):
        return bool(self.linkedin_token)

    def is_twitter_linked(self):
        return bool(self.twitter_access_token)

    def is_reddit_linked(self):
        return bool(self.reddit_refresh_token)

    def is_youtube_linked(self):
        return bool(self.youtube_token)

    def all_socials_linked(self):
        return all([
            self.is_linkedin_linked(),
            self.is_twitter_linked(),
            self.is_reddit_linked(),
            self.is_youtube_linked()
        ])