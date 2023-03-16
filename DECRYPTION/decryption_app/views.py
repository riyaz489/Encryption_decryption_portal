from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from .forms import Wru
from .managers import *


@login_required
def home(request):
    form = Wru(request.POST)
    if request.method == 'POST':
        if form.is_valid():
            selected = form.cleaned_data.get("options")

            if selected == '0':
                page = "decrypt_text"

            elif selected == '1':
                page = 'decrypt_image'

            elif selected == '2':
                page = 'decrypt_text_file'

            elif selected == '3':
                page = 'decrypt_zip'
            return redirect(page)
    return render(request, 'home.html', {'form': form})

@login_required
def decrypt_text(request):
    if request.method == 'POST':
        return generate_decoded_text_response(request)
    return render(request, 'decrypt_text.html')

@login_required
def decrypt_image(request):
    if request.method == 'POST' and request.FILES.get('encrypted_img'):
        return generate_decoded_image_response(request)
    return render(request, 'decode_image.html')


@login_required
def decrypt_text_file(request):
    if request.method == 'POST' and request.FILES.get('log_file'):
        return generate_decoded_log_file_response(request)
    return render(request, 'decode_log.html')


@login_required
def upload_zip(request):
    if request.method == 'POST' and request.FILES.get('zip_file'):
        return generate_decoded_zip_response(request)
    return render(request, 'decode_zip.html')


def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', None)
        password = request.POST.get('password', None)
        try:
            result = handle_login(request, email=email, password=password)
            if result:
                # if login success then go to next url or if next is none then go to home url
                return redirect(request.GET.get('next', '/'))
            else:
                return render(request, 'login.html', {'fail': 'Invalid Credentials', 'next': request.GET.get('next', '/')})
        except:
            return render(request, 'login.html', {'error': 'Some Error occurred while login', 'next': request.GET.get('next', '/')})

    return render(request, 'login.html', {'next': request.GET.get('next', '/')})


