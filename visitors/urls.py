from django.urls import path
from . import views

app_name = 'visitors'

urlpatterns = [
    path('', views.visitor_list, name='visitor_list'),
    path('new/', views.visitor_create, name='visitor_create'),
    path('export/', views.export_visitors_excel, name='export_visitors'),
]
