import os
from pathlib import Path
from django.conf import settings
from dotenv import load_dotenv
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = os.path.join(BASE_DIR,'template')
STATIC_DIR = os.path.join(BASE_DIR,'static')
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "j9k*spule$g6&dnpf26w@l*jkelj&dhvhry@r%4=^(i0-hyg99")
DEBUG = os.environ.get("DEBUG", "False") == "True"
ALLOWED_HOSTS = [
    "social-media-dashboard-1-j8vi.onrender.com",
    "localhost",
    "127.0.0.1",
    "*",
]
CSRF_TRUSTED_ORIGINS = [
    "https://social-media-dashboard-1-j8vi.onrender.com"
]
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    'core',
]
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "social_dashboard.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
WSGI_APPLICATION = "social_dashboard.wsgi.application"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}
CSRF_TRUSTED_ORIGINS = [
    "https://social-media-dashboard-f5bw.onrender.com"
]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True
LOGIN_URL = '/login/'
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
os.makedirs(os.path.join(settings.MEDIA_ROOT, 'profile_pics'), exist_ok=True)
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI")
TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
TWITTER_REDIRECT_URI = os.getenv("TWITTER_REDIRECT_URI")
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET")
REDDIT_REDIRECT_URI = os.getenv("REDDIT_REDIRECT_URI")
YOUTUBE_CLIENT_ID = os.getenv("YOUTUBE_CLIENT_ID")
YOUTUBE_CLIENT_SECRET = os.getenv("YOUTUBE_CLIENT_SECRET")
YOUTUBE_REDIRECT_URI = os.getenv("YOUTUBE_REDIRECT_URI")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
EMAIL_VERIFICATION_API_KEY = os.getenv("EMAIL_VERIFICATION_API_KEY")
EMAIL_VERIFICATION_API_URL = os.getenv("EMAIL_VERIFICATION_API_URL")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
SNAPCHAT_CLIENT_ID = os.getenv("SNAPCHAT_CLIENT_ID")
SNAPCHAT_CLIENT_SECRET = os.getenv("SNAPCHAT_CLIENT_SECRET")
SNAPCHAT_REDIRECT_URI = os.getenv("SNAPCHAT_REDIRECT_URI")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
PINTEREST_CLIENT_ID = os.getenv("PINTEREST_CLIENT_ID")
PINTEREST_CLIENT_SECRET = os.getenv("PINTEREST_CLIENT_SECRET")
PINTEREST_REDIRECT_URI = os.getenv("PINTEREST_REDIRECT_URI")