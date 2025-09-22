from django.contrib import admin
from .models import Visitor

@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = ('id', 'first_name', 'last_name', 'mobile', 'num_people', 'created_at')
    search_fields = ('first_name', 'middle_name', 'last_name', 'mobile')
