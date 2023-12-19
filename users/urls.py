from django.urls import path, include
from . import views


urlpatterns = [
    path('', views.home, name = 'home'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('signup',views.signup, name='signup'),
    path('signin',views.signin, name='signin'),
    path('signout',views.signout, name='signout'),



    path('company-signup/', views.company_signup, name='company-signup'),
    path('company_activate/<str:uidb64>/<str:token>/', views.company_activate, name='company_activate'),
    path('company-signin/', views.company_signin, name='company-signin'),
]