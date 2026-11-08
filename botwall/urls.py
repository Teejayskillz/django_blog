from django.urls import path

from . import views

app_name = "botwall"

urlpatterns = [
    path("challenge/", views.challenge_info, name="challenge"),
    path("challenge/verify/", views.challenge_verify, name="challenge_verify"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("dashboard/series/", views.traffic_series, name="traffic_series"),
    path("dashboard/ban/", views.ban_ip, name="ban_ip"),
    path("dashboard/unban/", views.unban_ip, name="unban_ip"),
    path("dashboard/whitelist/", views.whitelist_ip, name="whitelist_ip"),
]
