from django.urls import path
from .views import home, decrypt_text, decrypt_image, decrypt_text_file, upload_zip, login_view
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', home, name='home'),
    path('decrypt_image/', decrypt_image, name='decrypt_image'),
    path('decrypt_text/', decrypt_text, name='decrypt_text'),
    path('decrypt_text_file/', decrypt_text_file, name='decrypt_text_file'),
    path('decrypt_zip/', upload_zip, name='decrypt_zip'),
    # path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('login/', login_view, name='login'),

]