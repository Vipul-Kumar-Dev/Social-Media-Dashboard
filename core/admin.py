from django.contrib import admin
from .models import Profile

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        'get_username',
        'get_email',
        'masked_password',
        'phone_number',
        'otp_temp_phone',
        'otp_code',
        'otp_created_at'
    )
    search_fields = ('user__username', 'user__email', 'phone_number', 'otp_temp_phone')

    def get_username(self, obj):
        return obj.user.username
    get_username.short_description = 'Username'

    def get_email(self, obj):
        return obj.user.email
    get_email.short_description = 'Email'

    def masked_password(self, obj):
        return '********'
    masked_password.short_description = 'Password'
