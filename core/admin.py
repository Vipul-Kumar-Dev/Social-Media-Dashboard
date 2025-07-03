from django.contrib import admin
from .models import Profile

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone', 'otp_temp_phone', 'otp_code', 'otp_created_at')
    search_fields = ('user__username', 'phone', 'otp_temp_phone')
