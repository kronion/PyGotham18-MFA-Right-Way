from django.contrib.auth.views import LogoutView
from django.urls import path

from django_mfa_example import views as base_views
from users import views as user_views


urlpatterns = [
    path('', base_views.index, name='index'),
    path('login/', user_views.MaybeLoginView.as_view(), name='login'),
    path('login/token/', user_views.OTPView.as_view(), name='token'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', user_views.ProfileView.as_view(), name='profile'),
]
