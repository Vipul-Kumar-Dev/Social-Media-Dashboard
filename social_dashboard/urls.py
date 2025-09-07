from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('check-username/', views.check_username, name='check_username'),
    path('check-email/', views.check_email, name='check_email'),
    path('link/<str:platform>/', views.link_social, name='link_social'),
    path('unlink/<str:platform>/', views.unlink_social, name='unlink_social'),
    path('verify-email/<uidb64>/<token>/', views.verify_email_view, name='verify_email'),
    path('send_verification_email/', views.send_verification_email, name='send_verification_email'),
    path('test-email/', views.test_email, name='test_email'),
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    
    # Facebook
    path('facebook/login/', views.facebook_auth_start, name='facebook_auth_start'),
    path('facebook/callback/', views.facebook_callback, name='facebook_callback'),
    path('facebook/exchange_long_lived_token/', views.exchange_long_lived_token, name='exchange_long_lived_token'),
    path('facebook/fetch_user_data/', views.fetch_facebook_user_data, name='fetch_facebook_user_data'),

    # LinkedIn
    path('link/linkedin/', views.linkedin_auth_start, name='linkedin_auth_start'),
    path('linkedin/callback/', views.linkedin_callback, name='linkedin_callback'),
    path('linkedin/login/', views.linkedin_login, name='linkedin_login'),

    # Twitter
    path('twitter/callback/', views.twitter_callback, name='twitter_callback'),
    path('twitter/login/', views.twitter_login, name='twitter_login'),

    # Reddit
    path("reddit/login/", views.reddit_auth_start, name="reddit_auth_start"),
    path("reddit/callback/", views.reddit_callback, name="reddit_callback"),

    # YouTube
    path('youtube_auth_start', views.youtube_auth_start, name='youtube_auth_start'),
    path('youtube/callback/', views.youtube_callback, name='youtube_callback'),

    # GitHub
    path('github/login/', views.github_auth_start, name='github_auth_start'),
    path('github/callback/', views.github_callback, name='github_callback'),

    # Snapchat
    path('snapchat/login/', views.snapchat_auth_start, name='snapchat_auth_start'),
    path('snapchat/callback/', views.snapchat_callback, name='snapchat_callback'),

    # Password reset
    path('forgot-password/', views.forgot_password_view, name='password_reset'),
    path('send-otp-forgot/', views.send_otp_forgot, name='send_otp_forgot'),
    path('verify-otp-forgot/', views.verify_otp_forgot, name='verify_otp_forgot'),
    path('reset-password/', views.reset_password_view, name='reset_password'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
