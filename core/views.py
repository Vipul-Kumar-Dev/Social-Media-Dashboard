import base64
import re
from typing import Counter
from arrow import now
import os
from django.views.decorators.csrf import csrf_exempt
from dotenv import load_dotenv
import praw
import hashlib
import secrets
import jwt
import random
import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.models import User
import urllib
from social_dashboard.settings import EMAIL_VERIFICATION_API_KEY, EMAIL_VERIFICATION_API_URL, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
from .forms import ProfileUpdateForm
from django.contrib.auth import logout as auth_logout
from .models import Profile
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from datetime import datetime, timedelta
from twilio.rest import Client
from django.utils import timezone
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
from .forms import ProfileUpdateForm
from datetime import timedelta
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
import requests
from django.contrib.auth import get_user_model
from twilio.rest import Client
User = get_user_model()
@login_required
def dashboard(request):
    profile = request.user.profile
    linkedin_data = None
    twitter_data = None
    reddit_data = None
    youtube_data = None
    github_data = None
    snapchat_data = None
    facebook_data = None

    if profile.linkedin_token:
        headers = {"Authorization": f"Bearer {profile.linkedin_token}"}
        try:
            resp = requests.get("https://api.linkedin.com/v2/userinfo", headers=headers, timeout=10)
            if resp.status_code == 200:
                user_info = resp.json()
                linkedin_data = {
                    "name": user_info.get("name"),
                    "email": user_info.get("email"),
                    "picture": user_info.get("picture"),
                    "sub": user_info.get("sub")
                }
            else:
                linkedin_data = {"error": f"Failed to fetch LinkedIn data ({resp.status_code})"}
        except Exception as e:
            linkedin_data = {"error": str(e)}

    if profile.twitter_access_token:
        headers = {"Authorization": f"Bearer {profile.twitter_access_token}"}
        try:
            user_resp = requests.get(
                "https://api.twitter.com/2/users/me?user.fields=profile_image_url,public_metrics,description,created_at",
                headers=headers, timeout=10
            )
            if user_resp.status_code == 200:
                user_data = user_resp.json().get("data", {})
                twitter_data = {
                    "id": user_data.get("id"),
                    "name": user_data.get("name"),
                    "username": user_data.get("username"),
                    "profile_image": user_data.get("profile_image_url"),
                    "description": user_data.get("description"),
                    "created_at": user_data.get("created_at"),
                    "followers_count": user_data.get("public_metrics", {}).get("followers_count"),
                    "following_count": user_data.get("public_metrics", {}).get("following_count"),
                    "tweets_count": user_data.get("public_metrics", {}).get("tweet_count"),
                }
            else:
                twitter_data = {"error": f"Failed to fetch Twitter data ({user_resp.status_code})"}
        except Exception as e:
            twitter_data = {"error": str(e)}

    if profile.reddit_access_token:
        headers = {
            "Authorization": f"Bearer {profile.reddit_access_token}",
            "User-Agent": "SocialMediaDashboard/1.0"
        }
        try:
            user_resp = requests.get("https://oauth.reddit.com/api/v1/me", headers=headers, timeout=10)
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                reddit_data = {
                    "name": user_data.get("name"),
                    "link_karma": user_data.get("link_karma"),
                    "comment_karma": user_data.get("comment_karma"),
                    "total_karma": user_data.get("total_karma"),
                    "verified": user_data.get("verified"),
                    "created_utc": datetime.utcfromtimestamp(user_data.get("created_utc")),
                    "has_verified_email": user_data.get("has_verified_email"),
                    "icon_img": user_data.get("icon_img", "")
                }
            else:
                reddit_data = {"error": f"Failed to fetch Reddit data ({user_resp.status_code})"}
        except Exception as e:
            reddit_data = {"error": str(e)}

    if profile.youtube_token:
        headers = {
            "Authorization": f"Bearer {profile.youtube_token}",
            "Accept": "application/json"
        }
        try:
            yt_resp = requests.get(
                "https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
                headers=headers,
                timeout=10
            )
            if yt_resp.status_code == 200:
                data = yt_resp.json()
                if "items" in data and data["items"]:
                    item = data["items"][0]
                    youtube_data = {
                        "channel_title": item["snippet"]["title"],
                        "thumbnail": item["snippet"]["thumbnails"]["default"]["url"],
                        "subscriber_count": item["statistics"].get("subscriberCount", 0),
                        "view_count": item["statistics"].get("viewCount", 0),
                        "video_count": item["statistics"].get("videoCount", 0),
                        "top_videos": []
                    }
                else:
                    youtube_data = {"error": "No YouTube channel found on this account."}
            else:
                try:
                    error_msg = yt_resp.json().get("error", {}).get("message", "Unknown error.")
                except Exception as e:
                    error_msg = f"Error parsing response: {str(e)}"
                youtube_data = {"error": f"Failed to fetch YouTube data: {error_msg}"}
        except Exception as e:
            youtube_data = {"error": f"Exception occurred while fetching YouTube data: {str(e)}"}

    if profile.github_token:
        headers = {
            "Authorization": f"token {profile.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        try:
            github_resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
            if github_resp.status_code == 200:
                user_data = github_resp.json()
                repos_resp = requests.get("https://api.github.com/user/repos?per_page=5&sort=updated", headers=headers, timeout=10)
                repos_list = []
                if repos_resp.status_code == 200:
                    repos_data = repos_resp.json()
                    for repo in repos_data:
                        repos_list.append({
                            "name": repo.get("name"),
                            "html_url": repo.get("html_url"),
                            "language": repo.get("language"),
                            "stargazers_count": repo.get("stargazers_count"),
                            "forks_count": repo.get("forks_count"),
                            "updated_at": repo.get("updated_at")
                        })
                github_data = {
                    "username": user_data.get("login"),
                    "avatar_url": user_data.get("avatar_url"),
                    "public_repos": user_data.get("public_repos"),
                    "followers": user_data.get("followers"),
                    "following": user_data.get("following"),
                    "repos": repos_list
                }
            else:
                github_data = {"error": f"Failed to fetch GitHub data ({github_resp.status_code})"}
        except Exception as e:
            github_data = {"error": str(e)}

    if profile.snapchat_access_token:
        try:
            headers = {
                "Authorization": f"Bearer {profile.snapchat_access_token}",
                "Content-Type": "application/json",
            }
            resp = requests.get("https://kit.snapchat.com/v1/me", headers=headers, timeout=10)
            if resp.status_code == 200:
                me_data = resp.json().get("data", {}).get("me", {})
                snapchat_data = {
                    "display_name": me_data.get("displayName"),
                    "external_id": me_data.get("externalId"),
                    "bitmoji_avatar": me_data.get("bitmoji", {}).get("avatar"),
                    "bitmoji_selfie_id": me_data.get("bitmoji", {}).get("selfieId"),
                    "bitmoji_background_id": me_data.get("bitmoji", {}).get("backgroundId"),
                }
            else:
                snapchat_data = {"error": f"Failed to fetch Snapchat data ({resp.status_code}): {resp.text}"}
        except Exception as e:
            snapchat_data = {"error": str(e)}

    if profile.facebook_token:
        access_token = profile.facebook_token
        fields = [
            "id",
            "name",
            "email",
            "birthday",
            "age_range",
            "gender",
            "link",
            "friends",
            "hometown",
            "location",
            "likes",
            "photos",
            "videos",
            "posts"
        ]
        url = f"https://graph.facebook.com/me?fields={','.join(fields)}&access_token={access_token}"
        try:
            resp = requests.get(url, timeout=10).json()
            if "error" in resp:
                facebook_data = {"error": resp["error"].get("message", "Failed to fetch data")}
            else:
                facebook_data = {
                    "name": resp.get("name"),
                    "email": resp.get("email"),
                    "birthday": resp.get("birthday"),
                    "age_range": resp.get("age_range"),
                    "gender": resp.get("gender"),
                    "link": resp.get("link"),
                    "friends_count": len(resp.get("friends", {}).get("data", [])) if "friends" in resp else None,
                    "hometown": resp.get("hometown", {}).get("name") if "hometown" in resp else None,
                    "location": resp.get("location", {}).get("name") if "location" in resp else None,
                    "likes_count": len(resp.get("likes", {}).get("data", [])) if "likes" in resp else None,
                    "photos_count": len(resp.get("photos", {}).get("data", [])) if "photos" in resp else None,
                    "videos_count": len(resp.get("videos", {}).get("data", [])) if "videos" in resp else None,
                    "posts_count": len(resp.get("posts", {}).get("data", [])) if "posts" in resp else None
                }
        except Exception as e:
            facebook_data = {"error": str(e)}

    return render(request, 'dashboard.html', {
        'linkedin_data': linkedin_data,
        'twitter_data': twitter_data,
        'reddit_data': reddit_data,
        'youtube_data': youtube_data,
        'github_data': github_data,
        'snapchat_data': snapchat_data,
        'facebook_data': facebook_data,
    })
def verify_email(email):
    try:
        params = {
            'secret': EMAIL_VERIFICATION_API_KEY,
            'email': email
        }
        response = requests.get(EMAIL_VERIFICATION_API_URL, params=params, timeout=10)
        result = response.text.strip().lower()
        return result == 'ok'
    except requests.exceptions.RequestException as e:
        return False
def is_strong_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]).{8,}$'
    return re.match(pattern, password)
def register(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone = request.POST.get('phone')
        if not all([name, email, username, password, confirm_password, phone]):
            messages.error(request, "All fields are required.")
            return render(request, "register.html")
        if not re.match(r'^\d{10}$', phone):
            messages.error(request, "Enter a valid 10-digit phone number.")
            return render(request, "register.html")
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "register.html")
        if not is_strong_password(password):
            messages.error(request, "Password must include an uppercase letter, a number, and a special character.")
            return render(request, "register.html")
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return render(request, "register.html")
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken.")
            return render(request, "register.html")
        if not verify_email(email):
            messages.error(request, "Please enter a valid, deliverable email address.")
            return render(request, "register.html")
        user = User.objects.create_user(
            first_name=name,
            email=email,
            username=username,
            password=password
        )
        Profile.objects.get_or_create(user=user, defaults={'phone_number': phone})
        login(request, user)
        messages.success(request, "Registration successful! Please log in to continue.")
        return redirect('login')
    return render(request, "register.html")
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            messages.success(request, "Logged in successfully.")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})
@login_required
def profile(request):
    user = request.user
    profile, _ = Profile.objects.get_or_create(user=user)

    reddit_data = None
    youtube_data = None
    snapchat_data = None

    # === REDDIT ===
    if profile.reddit_access_token:
        try:
            resp = requests.get(
                "https://oauth.reddit.com/api/v1/me",
                headers={
                    "Authorization": f"Bearer {profile.reddit_access_token}",
                    "User-Agent": "django:test:v1.0 by Kunal"
                },
                timeout=10
            )
            reddit_data = resp.json() if resp.status_code == 200 else {
                "error": f"⚠️ Reddit error: {resp.status_code}"}
        except Exception as e:
            reddit_data = {"error": f"⚠️ Reddit exception: {str(e)}"}

    # === YOUTUBE ===
    if profile.youtube_token:
        try:
            yt_resp = requests.get(
                "https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
                headers={
                    "Authorization": f"Bearer {profile.youtube_token}",
                    "Accept": "application/json"
                },
                timeout=10
            )
            if yt_resp.status_code == 200:
                data = yt_resp.json()
                if data.get("items"):
                    item = data["items"][0]
                    youtube_data = {
                        "channel_title": item["snippet"]["title"],
                        "thumbnail": item["snippet"]["thumbnails"]["default"]["url"],
                        "subscriber_count": item["statistics"].get("subscriberCount", 0),
                        "view_count": item["statistics"].get("viewCount", 0),
                        "video_count": item["statistics"].get("videoCount", 0),
                        "top_videos": []
                    }
                else:
                    youtube_data = {"error": "⚠️ No YouTube channel found."}
            else:
                try:
                    error_msg = yt_resp.json().get("error", {}).get("message", "Unknown error.")
                except Exception as e:
                    error_msg = f"Error parsing response: {str(e)}"
                youtube_data = {"error": f"⚠️ YouTube error: {yt_resp.status_code} – {error_msg}"}
        except Exception as e:
            youtube_data = {"error": f"⚠️ YouTube exception: {str(e)}"}

    # === SNAPCHAT ===
    if profile.snapchat_access_token:
        try:
            snap_resp = requests.get(
                "https://adsapi.snapchat.com/v1/me",
                headers={
                    "Authorization": f"Bearer {profile.snapchat_access_token}",
                    "Accept": "application/json"
                },
                timeout=10
            )
            snapchat_data = snap_resp.json() if snap_resp.status_code == 200 else {
                "error": f"⚠️ Snapchat error: {snap_resp.status_code}"}
        except Exception as e:
            snapchat_data = {"error": f"⚠️ Snapchat exception: {str(e)}"}

    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, request.FILES, instance=profile)
        new_username = request.POST.get("username")
        otp = request.POST.get("otp_code")
        errors = False

        if otp:
            if otp == profile.otp_code and profile.otp_created_at and now() - profile.otp_created_at < timedelta(minutes=5):
                profile.otp_code = ""
                profile.otp_created_at = None
                if profile.otp_temp_phone:
                    profile.phone_number = profile.otp_temp_phone
                    profile.otp_temp_phone = None
                    messages.success(request, "✅ Phone number updated successfully!")
                else:
                    messages.warning(request, "⚠️ No pending phone number to update.")
            else:
                messages.error(request, "⚠️ Invalid or expired OTP.")

        if new_username and new_username != user.username:
            if User.objects.filter(username=new_username).exclude(pk=user.pk).exists():
                messages.error(request, "⚠️ Username is already taken.")
                errors = True
            else:
                user.username = new_username
                user.save()
                messages.success(request, "✅ Username updated successfully!")

        if form.is_valid():
            form.save()
            profile.save()
        else:
            errors = True
            messages.error(request, "⚠️ Failed to update profile.")

        if not errors:
            messages.success(request, "✅ Profile updated successfully!")
            return redirect("profile")
    else:
        form = ProfileUpdateForm(instance=profile)

    return render(request, "profile.html", {
        "form": form,
        "profile": profile,
        "reddit_data": reddit_data,
        "youtube_data": youtube_data,
        "snapchat_data": snapchat_data,
    })

@login_required
def send_verification_email(request):
    email = request.GET.get('email')
    print("DEBUG EMAIL CHECK:", email)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
    if email:
        user = request.user
        profile = user.profile
        profile.unverified_email = email
        profile.email_verified = False
        profile.save()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        current_site = get_current_site(request).domain
        verification_link = f"http://{current_site}{reverse('verify_email', kwargs={'uidb64': uid, 'token': token})}"
        send_mail(
            subject="Verify your new email",
            message=f"Click the link below to verify your new email:\n{verification_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )
        return JsonResponse({'status': 'sent'})
    return JsonResponse({'status': 'error'})
def verify_email_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        profile = Profile.objects.get(user=user)
        if profile.unverified_email:
            user.email = profile.unverified_email
            user.save()
            profile.email_verified = True
            profile.unverified_email = ''
            profile.save()
        messages.success(request, "Email verified and updated successfully!")
        return redirect('profile')
    else:
        return HttpResponse('Verification link is invalid!', status=400)
@login_required
def link_social(request, platform):
    if platform == 'linkedin':
        import urllib.parse
        params = {
            'response_type': 'code',
            'client_id': settings.LINKEDIN_CLIENT_ID,
            'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
            'scope': 'openid profile email'
        }
        url = f"https://www.linkedin.com/oauth/v2/authorization?{urllib.parse.urlencode(params)}"
        return redirect(url)
    profile = request.user.profile
    if platform == 'instagram':
        profile.instagram_connected = True
    elif platform == 'facebook':
        profile.facebook_connected = True
    profile.save()
    messages.success(request, f"{platform.capitalize()} linked successfully!")
    return redirect('profile')
@login_required
def unlink_social(request, platform):
    profile = request.user.profile
    if platform == 'instagram':
        profile.instagram_token = ''
    elif platform == 'facebook':
        profile.facebook_token = ''
    elif platform == 'linkedin':
        profile.linkedin_token = ''
    profile.save()
    messages.info(request, f"{platform.capitalize()} unlinked.")
    return redirect('profile')
def check_username(request):
    username = request.GET.get('username', None)
    exists = User.objects.filter(username__iexact=username).exists()
    return JsonResponse({'exists': exists})
def check_email(request):
    email = request.GET.get('email')
    if not email:
        return JsonResponse({"valid": False, "reason": "No email provided"})
    try:
        response = requests.get(
            settings.EMAIL_VERIFICATION_API_URL,
            params={"api_key": settings.EMAIL_VERIFICATION_API_KEY, "email": email},
            timeout=3
        )
        data = response.json()
        if "error" in data:
            return JsonResponse({"valid": False, "reason": data["error"].get("message", "API error")})
        deliverability = data.get("deliverability", "").lower()
        return JsonResponse({
            "valid": deliverability in ["deliverable", "risky"],
            "reason": deliverability
        })
    except requests.exceptions.RequestException as e:
        return JsonResponse({"valid": False, "reason": str(e)})
def logout(request):
    auth_logout(request)
    messages.info(request, "Logged out successfully.")
    return redirect('login')
def test_email(request):
    send_mail(
        subject='Django Test',
        message='This is a test email from Django.',
        from_email='vipulsam1234@gmail.com',
        recipient_list=['vipulsam1234@gmail.com'],
        fail_silently=False,
    )
    return HttpResponse('Test email sent.')
def forgot_password_view(request):
    return render(request, 'forgot_password.html')
@require_GET
@login_required
def send_otp(request):
    phone_number = request.GET.get('phone')
    if not phone_number:
        return JsonResponse({'error': 'Phone number is required'}, status=400)
    otp = str(random.randint(100000, 999999))
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_number = os.getenv("TWILIO_PHONE_NUMBER")
    client = Client(account_sid, auth_token)
    try:
        message = client.messages.create(
            body=f"Your OTP is {otp}",
            from_=twilio_number,
            to=f"+91{phone_number}"
        )
        request.session['otp'] = otp
        profile = request.user.profile
        profile.otp_code = otp
        profile.otp_created_at = timezone.now()
        profile.otp_temp_phone = phone_number
        profile.save()
        return JsonResponse({'status': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
@require_POST
@login_required
def verify_otp(request):
    user = request.user
    profile = user.profile
    input_otp = request.POST.get('otp')
    new_password = request.POST.get('new_password')
    temp_phone = getattr(profile, 'otp_temp_phone', None)

    if not input_otp:
        return JsonResponse({'status': 'invalid', 'message': 'OTP is required.'})
    if profile.otp_code != input_otp:
        return JsonResponse({'status': 'invalid', 'message': 'Incorrect OTP.'})
    if timezone.now() - profile.otp_created_at > timedelta(minutes=5):
        return JsonResponse({'status': 'expired', 'message': 'OTP has expired. Please request a new one.'})
    if temp_phone and temp_phone != profile.phone_number:
        profile.phone_number = temp_phone
    profile.otp_temp_phone = ''
    profile.otp_code = ''
    profile.otp_created_at = None
    profile.save()
    request.session['otp_verified'] = True
    if not new_password:
        return JsonResponse({'status': 'verified', 'message': 'OTP verified successfully! Phone updated.'})
    if not is_strong_password(new_password):
        return JsonResponse({
            'status': 'weak_password',
            'message': 'Password must include at least 8 characters, one uppercase letter, one number, and one special character.'
        })
    user.set_password(new_password)
    user.save()
    return JsonResponse({'status': 'success', 'message': 'Password updated successfully!'})
@require_GET
def send_otp_forgot(request):
    phone_number = request.GET.get("phone")
    if not phone_number:
        return JsonResponse({'error': 'Phone number is required'}, status=400)
    try:
        profile = Profile.objects.get(phone_number=phone_number)
        if profile.otp_created_at and timezone.now() - profile.otp_created_at < timedelta(minutes=1):
            return JsonResponse({'status': 'wait', 'message': 'Please wait a minute before requesting another OTP.'})
        otp = str(random.randint(100000, 999999))
        profile.otp_code = otp
        profile.otp_created_at = timezone.now()
        profile.save()
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f"Your OTP for password reset is: {otp}",
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=f"+91{phone_number}"
        )
        return JsonResponse({'status': 'sent', 'message': 'OTP sent successfully!'})
    except Profile.DoesNotExist:
        return JsonResponse({'status': 'not_found', 'message': 'Phone number not registered.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@require_POST
def verify_otp_forgot(request):
    phone_number = request.POST.get("phone")
    otp_input = request.POST.get("otp")
    new_password = request.POST.get("new_password")
    if not phone_number or not otp_input:
        return JsonResponse({'status': 'invalid', 'message': 'Phone number and OTP are required.'})
    try:
        profile = Profile.objects.get(phone_number=phone_number)
        if profile.otp_code != otp_input:
            return JsonResponse({'status': 'invalid', 'message': 'Incorrect OTP.'})
        if timezone.now() - profile.otp_created_at > timedelta(minutes=5):
            return JsonResponse({'status': 'expired', 'message': 'OTP expired. Please try again.'})
        if not new_password:
            return JsonResponse({'status': 'verified', 'message': 'OTP verified successfully.'})
        def is_strong_password(password):
            if not password:
                return False
            return (
                len(password) >= 8 and
                any(c.isupper() for c in password) and
                any(c.islower() for c in password) and
                any(c.isdigit() for c in password) and
                any(not c.isalnum() for c in password)
            )
        if not is_strong_password(new_password):
            return JsonResponse({
                'status': 'weak_password',
                'message': 'Password must have at least 8 characters, 1 uppercase, 1 lowercase, 1 number, and 1 special character.'
            })
        user = profile.user
        user.set_password(new_password)
        user.save()
        profile.otp_code = ''
        profile.otp_created_at = None
        profile.save()
        return JsonResponse({'status': 'success', 'message': 'Password updated successfully!'})
    except Profile.DoesNotExist:
        return JsonResponse({'status': 'not_found', 'message': 'Phone number not registered.'})
from django.contrib.auth.hashers import make_password
def reset_password_view(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if password != confirm_password:
            return render(request, 'reset_password.html', {'error': 'Passwords do not match'})
        email = request.session.get('reset_email')
        if email:
            try:
                user = User.objects.get(email=email)
                user.password = make_password(password)
                user.save()
                request.session.pop('reset_email', None)
                return redirect('login')
            except User.DoesNotExist:
                return render(request, 'reset_password.html', {'error': 'User not found'})
        else:
            return render(request, 'reset_password.html', {'error': 'Session expired. Try again.'})
    return render(request, 'reset_password.html')
def is_strong_password(password):
    import re
    if not password:
        return False
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[^A-Za-z0-9]", password))
def linkedin_auth_start(request):
    redirect_uri = settings.LINKEDIN_REDIRECT_URI
    linkedin_url = (
        f"https://www.linkedin.com/oauth/v2/authorization"
        f"?response_type=code"
        f"&client_id={settings.LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=r_liteprofile%20r_emailaddress"
    )
    return redirect(linkedin_url)
@login_required
def linkedin_callback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponse("No code returned", status=400)
    token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
        'client_id': settings.LINKEDIN_CLIENT_ID,
        'client_secret': settings.LINKEDIN_CLIENT_SECRET,
    }
    try:
        response = requests.post(token_url, data=data, timeout=10)
        token_json = response.json()
        access_token = token_json.get('access_token')
        id_token = token_json.get('id_token')
        if not id_token:
            return HttpResponse(f"Failed to get id_token: {token_json}", status=400)
        payload = jwt.decode(id_token, options={"verify_signature": False})
        email = payload.get("email")
        sub = payload.get("sub")
        name = payload.get("name")
        profile = request.user.profile
        profile.linkedin_token = access_token
        profile.linkedin_connected = True
        profile.save()
        print("LINKEDIN DATA:", payload)
        messages.success(request, f"LinkedIn connected: {email or name}")
        return redirect('profile')
    except Exception as e:
        return HttpResponse(f"Error during LinkedIn flow: {e}", status=500)
def linkedin_login(request):
    params = {
        'response_type': 'code',
        'client_id': settings.LINKEDIN_CLIENT_ID,
        'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
        'scope': 'r_liteprofile r_emailaddress',
        'state': 'random123'
    }
    url = 'https://www.linkedin.com/oauth/v2/authorization?' + urllib.parse.urlencode(params)
    return redirect(url)
def twitter_login(request):
    request.session.pop('twitter_state', None)
    request.session.pop('twitter_code_verifier', None)
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    request.session['twitter_state'] = state
    request.session['twitter_code_verifier'] = code_verifier
    request.session.modified = True
    print("==== TWITTER LOGIN ====")
    print("state:", state)
    print("code_challenge:", code_challenge)
    print("SESSION SET:", dict(request.session))
    auth_url = (
        "https://twitter.com/i/oauth2/authorize"
        "?response_type=code"
        f"&client_id={settings.TWITTER_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(settings.TWITTER_REDIRECT_URI)}"
        f"&scope=tweet.read%20users.read%20offline.access"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        "&code_challenge_method=S256"
    )
    return redirect(auth_url)
def twitter_callback(request):
    code = request.GET.get("code")
    state = request.GET.get("state")
    session_state = request.session.get("twitter_state")
    code_verifier = request.session.get("twitter_code_verifier")
    print("==== TWITTER CALLBACK ====")
    print("Received state:", state)
    print("Session state:", session_state)
    print("SESSION DATA:", dict(request.session))
    if not state or state != session_state:
        return HttpResponse("State mismatch. Possible CSRF attack.", status=400)
    if not code:
        return HttpResponse("No code returned from Twitter.", status=400)
    client_creds = f"{settings.TWITTER_CLIENT_ID}:{settings.TWITTER_CLIENT_SECRET}"
    basic_auth = base64.b64encode(client_creds.encode()).decode()
    token_url = "https://api.twitter.com/2/oauth2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {basic_auth}"
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.TWITTER_REDIRECT_URI,
        "code_verifier": code_verifier
    }
    response = requests.post(token_url, headers=headers, data=data, timeout=10)
    token_data = response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token:
        return JsonResponse({
            "error": "Failed to get access token from Twitter",
            "details": token_data
        }, status=400)
    user_info_response = requests.get(
        "https://api.twitter.com/2/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10
    )
    if user_info_response.status_code != 200:
        return JsonResponse({
            "error": "Failed to fetch Twitter user info",
            "details": user_info_response.text
        }, status=400)
    user_info = user_info_response.json()
    twitter_data = user_info.get("data", {})
    twitter_user_id = twitter_data.get("id")
    twitter_username = twitter_data.get("username")
    profile = request.user.profile
    profile.twitter_access_token = access_token
    profile.twitter_refresh_token = refresh_token
    profile.twitter_user_id = twitter_user_id
    profile.twitter_username = twitter_username
    profile.twitter_token_updated_at = timezone.now()
    profile.save()
    request.session.pop("twitter_state", None)
    request.session.pop("twitter_code_verifier", None)
    messages.success(request, "Twitter account linked successfully!")
    return redirect("profile")
def reddit_auth_start(request):
    client_id = settings.REDDIT_CLIENT_ID
    redirect_uri = settings.REDDIT_REDIRECT_URI
    state = "s3zK5x5rrNgA0Fo_RGewFA"
    auth_url = "https://www.reddit.com/api/v1/authorize"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "state": state,
        "redirect_uri": redirect_uri,
        "duration": "permanent",
        "scope": "identity read history"
    }
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")
@login_required
def reddit_callback(request):
    code = request.GET.get("code")
    if not code:
        messages.error(request, "Error: No code returned from Reddit.")
        return redirect("profile")
    client_id = settings.REDDIT_CLIENT_ID
    secret = settings.REDDIT_CLIENT_SECRET
    redirect_uri = settings.REDDIT_REDIRECT_URI
    auth = requests.auth.HTTPBasicAuth(client_id, secret)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "User-Agent": "django:test:v1.0 by Kunal",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    token_resp = requests.post("https://www.reddit.com/api/v1/access_token", auth=auth, data=data, headers=headers)
    try:
        token_data = token_resp.json()
    except Exception:
        messages.error(request, "Reddit returned an invalid response while fetching token.")
        return redirect("profile")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token:
        messages.error(request, f"Error fetching token from Reddit: {token_data}")
        return redirect("profile")
    user_headers = {
        "Authorization": f"bearer {access_token}",
        "User-Agent": "django:test:v1.0 by Kunal"
    }
    user_resp = requests.get("https://oauth.reddit.com/api/v1/me", headers=user_headers)
    try:
        user_data = user_resp.json()
    except Exception:
        messages.error(request, "Failed to fetch Reddit user profile.")
        return redirect("profile")
    try:
        profile = request.user.profile
        profile.reddit_access_token = access_token
        if refresh_token:
            profile.reddit_refresh_token = refresh_token
        profile.reddit_username = user_data.get("name", "")
        profile.reddit_token_updated_at = timezone.now()
        profile.save()
        messages.success(request, f"Reddit account (@{profile.reddit_username}) linked successfully!")
    except Exception as e:
        messages.error(request, f"Error saving Reddit data: {str(e)}")
    return redirect("profile")
def youtube_auth_start(request):
    params = {
        "client_id": settings.YOUTUBE_CLIENT_ID,
        "redirect_uri": settings.YOUTUBE_REDIRECT_URI,
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/youtube.readonly",
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")
@login_required
def youtube_callback(request):
    code = request.GET.get("code")
    if not code:
        messages.error(request, "No authorization code received.")
        return redirect("profile")
    data = {
        "code": code,
        "client_id": settings.YOUTUBE_CLIENT_ID,
        "client_secret": settings.YOUTUBE_CLIENT_SECRET,
        "redirect_uri": settings.YOUTUBE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    token_response = requests.post("https://oauth2.googleapis.com/token", data=data)
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token:
        messages.error(request, f"Token Error: {token_data}")
        return redirect("profile")
    try:
        profile = request.user.profile
        profile.youtube_token = access_token
        if refresh_token:
            profile.youtube_refresh_token = refresh_token
        profile.save()
        messages.success(request, "YouTube account linked successfully!")
    except Exception as e:
        messages.error(request, f"Error saving token: {e}")
    return redirect("profile")
def fetch_youtube_channel_data(user):
    access_token = user.profile.youtube_token
    refresh_token = user.profile.youtube_refresh_token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    response = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
        headers=headers,
    )
    if response.status_code == 401 and refresh_token:
        new_token = refresh_youtube_token(refresh_token)
        if new_token:
            user.profile.youtube_token = new_token
            user.profile.save()
            headers["Authorization"] = f"Bearer {new_token}"
            response = requests.get(
                "https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
                headers=headers,
            )
    if response.status_code != 200:
        try:
            error_info = response.json()
            return {"error": error_info.get("error", {}).get("message", "Failed to fetch data")}
        except Exception:
            return {"error": "Unable to fetch YouTube data"}
    data = response.json()
    if "items" not in data or not data["items"]:
        return {"error": "No channel found for this account."}
    item = data["items"][0]
    return {
        "title": item["snippet"]["title"],
        "thumbnail": item["snippet"]["thumbnails"]["default"]["url"],
        "subscribers": item["statistics"].get("subscriberCount", 0),
        "views": item["statistics"].get("viewCount", 0),
        "videos": item["statistics"].get("videoCount", 0),
    }
def refresh_youtube_token(refresh_token):
    data = {
        "client_id": settings.YOUTUBE_CLIENT_ID,
        "client_secret": settings.YOUTUBE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    response = requests.post("https://oauth2.googleapis.com/token", data=data)
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        return None
def github_auth_start(request):
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "allow_signup": "true",
    }
    auth_url = "https://github.com/login/oauth/authorize"
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")
@login_required
def github_callback(request):
    code = request.GET.get("code")
    if not code:
        messages.error(request, "No authorization code received from GitHub.")
        return redirect("profile")
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
    }
    headers = {"Accept": "application/json"}
    token_response = requests.post("https://github.com/login/oauth/access_token", data=data, headers=headers)
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    if not access_token:
        messages.error(request, f"GitHub Token Error: {token_data}")
        return redirect("profile")
    try:
        profile = request.user.profile
        profile.github_token = access_token
        profile.save()
        messages.success(request, "GitHub account linked successfully!")
    except Exception as e:
        messages.error(request, f"Error saving GitHub token: {e}")
    return redirect("profile")
def fetch_github_account_data(user):
    access_token = user.profile.github_token
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json"
    }
    github_data = {}
    user_resp = requests.get("https://api.github.com/user", headers=headers)
    if user_resp.status_code != 200:
        return {"error": f"Failed to fetch GitHub profile ({user_resp.status_code})"}
    profile = user_resp.json()
    github_data["profile"] = {
        "username": profile.get("login", ""),
        "name": profile.get("name", ""),
        "avatar_url": profile.get("avatar_url", ""),
        "bio": profile.get("bio", ""),
        "location": profile.get("location", ""),
        "blog": profile.get("blog", ""),
        "company": profile.get("company", ""),
        "created_at": profile.get("created_at", ""),
        "public_repos": profile.get("public_repos", 0),
        "public_gists": profile.get("public_gists", 0),
        "followers": profile.get("followers", 0),
        "following": profile.get("following", 0)
    }
    repos_resp = requests.get("https://api.github.com/user/repos?per_page=100&sort=updated", headers=headers)
    if repos_resp.status_code == 200:
        repos = repos_resp.json()
        github_data["repositories"] = [
            {
                "name": r.get("name"),
                "html_url": r.get("html_url"),
                "description": r.get("description"),
                "language": r.get("language"),
                "stargazers_count": r.get("stargazers_count", 0),
                "forks_count": r.get("forks_count", 0),
                "updated_at": r.get("updated_at")
            }
            for r in repos
        ]
        languages = [r.get("language") for r in repos if r.get("language")]
        github_data["top_languages"] = Counter(languages).most_common(6)
        github_data["total_stars"] = sum(r.get("stargazers_count", 0) for r in repos)
        github_data["top_repos"] = [
            {
                "name": r.get("name"),
                "html_url": r.get("html_url"),
                "stars": r.get("stargazers_count", 0),
                "language": r.get("language")
            }
            for r in sorted(repos, key=lambda x: x.get("stargazers_count", 0), reverse=True)[:6]
        ]
    orgs_resp = requests.get("https://api.github.com/user/orgs", headers=headers)
    if orgs_resp.status_code == 200:
        github_data["organizations"] = [
            {
                "login": o.get("login"),
                "avatar_url": o.get("avatar_url"),
                "html_url": f"https://github.com/{o.get('login')}"
            }
            for o in orgs_resp.json()
        ]
    gists_resp = requests.get("https://api.github.com/gists", headers=headers)
    if gists_resp.status_code == 200:
        github_data["gists"] = [
            {
                "id": g.get("id"),
                "html_url": g.get("html_url"),
                "created_at": g.get("created_at"),
                "files": list(g.get("files", {}).keys())
            }
            for g in gists_resp.json()
        ]
    events_resp = requests.get(f"https://api.github.com/users/{profile['login']}/events", headers=headers)
    if events_resp.status_code == 200:
        github_data["recent_activity"] = [
            {
                "type": e.get("type"),
                "repo": e.get("repo", {}).get("name"),
                "created_at": e.get("created_at")
            }
            for e in events_resp.json()
        ]
    return github_data
@login_required
def snapchat_auth_start(request):
    params = {
        "client_id": settings.SNAPCHAT_CLIENT_ID,
        "redirect_uri": settings.SNAPCHAT_REDIRECT_URI,
        "response_type": "code",
        "scope": "user.display_name user.bitmoji.avatar",
        "state": "secure_random_state_123",
    }
    auth_url = "https://accounts.snapchat.com/login/oauth2/authorize"
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")
@login_required
def snapchat_callback(request):
    code = request.GET.get("code")
    if not code:
        messages.error(request, "No authorization code received from Snapchat.")
        return redirect("profile")
    data = {
        "code": code,
        "client_id": settings.SNAPCHAT_CLIENT_ID,
        "client_secret": settings.SNAPCHAT_CLIENT_SECRET,
        "redirect_uri": settings.SNAPCHAT_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    token_response = requests.post("https://accounts.snapchat.com/login/oauth2/access_token", data=data)
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    if not access_token:
        messages.error(request, f"Snapchat Token Error: {token_data}")
        return redirect("profile")
    try:
        profile = request.user.profile
        profile.snapchat_access_token = access_token
        profile.snapchat_refresh_token = refresh_token
        profile.snapchat_access_token_expires_in = expires_in
        profile.save()
        messages.success(request, "Snapchat account linked successfully!")
    except Exception as e:
        messages.error(request, f"Error saving Snapchat token: {e}")
    return redirect("profile")
def fetch_snapchat_account_data(user):
    """Fetch all Snapchat data possible for dashboard."""
    access_token = user.profile.snapchat_access_token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    user_resp = requests.get("https://kit.snapchat.com/v1/me", headers=headers)
    if user_resp.status_code != 200:
        return {"error": "Failed to fetch Snapchat data"}
    user_data = user_resp.json().get("data", {}).get("me", {})
    dashboard_data = {
        "display_name": user_data.get("displayName", ""),
        "external_id": user_data.get("externalId", ""),
        "bitmoji_avatar": user_data.get("bitmoji", {}).get("avatar", ""),
        "bitmoji_selfie_id": user_data.get("bitmoji", {}).get("selfieId", ""),
        "bitmoji_background_id": user_data.get("bitmoji", {}).get("backgroundId", ""),
    }
    return dashboard_data
@login_required
def facebook_auth_start(request):
    params = {
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "redirect_uri": settings.FACEBOOK_REDIRECT_URI,
        "scope": ",".join([
            "email",
            "public_profile",
            "user_hometown",
            "user_birthday",
            "user_age_range",
            "user_gender",
            "user_link",
            "user_friends",
            "user_location",
            "user_likes",
            "user_photos",
            "user_videos",
            "user_posts"
        ]),
        "response_type": "code",
        "auth_type": "rerequest",
    }
    auth_url = "https://www.facebook.com/v18.0/dialog/oauth"
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")

@login_required
def facebook_callback(request):
    code = request.GET.get("code")
    if not code:
        messages.error(request, "No authorization code received.")
        return redirect("profile")
    token_url = "https://graph.facebook.com/v18.0/oauth/access_token"
    params = {
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "redirect_uri": settings.FACEBOOK_REDIRECT_URI,
        "client_secret": settings.FACEBOOK_CLIENT_SECRET,
        "code": code,
    }
    response = requests.get(token_url, params=params)
    data = response.json()
    access_token = data.get("access_token")
    if not access_token:
        messages.error(request, f"Token Error: {data}")
        return redirect("profile")
    try:
        profile = request.user.profile
        profile.facebook_token = access_token
        profile.save()
        messages.success(request, "Facebook/Instagram account linked successfully!")
    except Exception as e:
        messages.error(request, f"Error saving token: {e}")
    return redirect("profile")

def exchange_long_lived_token(short_token):
    url = "https://graph.facebook.com/v18.0/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "client_secret": settings.FACEBOOK_CLIENT_SECRET,
        "fb_exchange_token": short_token,
    }
    response = requests.get(url, params=params)
    return response.json().get("access_token")

def fetch_facebook_user_data(user):
    access_token = user.profile.facebook_token
    if not access_token:
        return {"error": "No Facebook token found."}
    fields = [
        "id",
        "name",
        "email",
        "birthday",
        "age_range",
        "gender",
        "link",
        "friends",
        "hometown",
        "location",
        "likes",
        "photos",
        "videos",
        "posts"
    ]
    url = f"https://graph.facebook.com/me?fields={','.join(fields)}&access_token={access_token}"
    resp = requests.get(url).json()
    if "error" in resp:
        return {"error": resp["error"].get("message", "Failed to fetch data")}
    return resp