import base64
import imghdr
import mimetypes
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from wsgiref.util import FileWrapper

from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.models import User
from django.core.files import File
from django.core.files.temp import NamedTemporaryFile
from django.http import StreamingHttpResponse
from django.shortcuts import render
from django_python3_ldap import ldap
from django_python3_ldap.auth import LDAPBackend
from django_python3_ldap.conf import settings

from helpers.decryption_utility import helper_decrypt_image, decrypt_log_file, helper_decrypt_text
from helpers.key_util import get_encryption_key, get_Key_encryption_key, unwrap_dek
from logging import getLogger
from tempfile import TemporaryDirectory


logger = getLogger(__name__)


def generate_decoded_text_response(request):
    try:
        cipher_text = request.POST['cipher_text']
        temp = re.findall("{{(.*?)}}", cipher_text)
        if len(temp) == 0:
            return render(request, 'decrypt_text.html', {
                'error': 'Not a valid cipher'
            })

        decoded_text, vaild_cipher = helper_decrypt_text(temp[0], {})
        if vaild_cipher:
            decoded_text = decoded_text.decode("utf-8")
            decoded_text = cipher_text.replace("{{" + temp[0] + "}}", decoded_text)
            return render(request, 'decrypt_text.html', {
                'result': decoded_text
            })
        else:
            return render(request, 'decrypt_text.html', {
                'error': 'Not a valid cipher'
            })
    except Exception as e:
        logger.error(e)
        return render(request, 'decrypt_text.html', {
            'error': 'some error occured'
        })


def generate_decoded_image_response(request):
    try:
        encrypted_img = request.FILES['encrypted_img']
        base64_data, _ = helper_decrypt_image(encrypted_img, {})
        base64_data = base64.b64encode(base64_data).decode('ascii')
        return render(request, 'decode_image.html', {'img_url': base64_data})
    except Exception as e:
        logger.error(e)
        return render(request, 'decode_image.html', {'error': 'can not decode this file'})


def generate_decoded_log_file_response(request):
    log_file = request.FILES['log_file']
    try:
        new_files = decrypt_log_file(log_file, {})
        # FileWrapper will read data in chunks of 8192
        response = StreamingHttpResponse(FileWrapper(open(new_files, 'rb')),
                                         content_type=mimetypes.guess_type(log_file.name)[0])
        response['Content-Length'] = os.path.getsize(new_files)
        response['Content-Disposition'] = "attachment; filename=%s" % log_file.name
        return response
    except Exception as e:
        logger.error(e)
        return render(request, 'decode_log.html', {'error': 'can not decode this file'})


def generate_decoded_zip_response(request):
    zip_file = request.FILES['zip_file']
    keymap_dict = {}
    if zipfile.is_zipfile(zip_file):
        try:
            temp_dir = TemporaryDirectory()
            dest_dir = TemporaryDirectory()
            final_zip = NamedTemporaryFile(suffix='.zip')
            with zipfile.ZipFile(zip_file, 'r') as zip:
                zip.extractall(path=temp_dir.name)

            source_dir = Path(temp_dir.name)
            files = source_dir.iterdir()

            handle_different_files_decryption(files, dest_dir, keymap_dict)

            with zipfile.ZipFile(final_zip.name, 'w') as zip:
                source_dir = Path(dest_dir.name)
                files = source_dir.iterdir()
                for file in files:
                    zip.write(file, arcname=file.name)

            response = StreamingHttpResponse(FileWrapper(open(final_zip.name, 'rb')),
                                             content_type=mimetypes.guess_type(final_zip.name)[0])
            response['Content-Length'] = os.path.getsize(final_zip.name)
            response['Content-Disposition'] = "attachment; filename=%s" % zip_file.name
            return response

        except Exception as e:
            logger.error(e)

            return render(request, 'decode_image.html', {'error': "some error occurred while decoding zip content"})

    else:
        return render(request, 'decode_image.html', {'error': "Not a zip file"})


def handle_different_files_decryption(files, destination_dir, key_map):
    for file in files:
        with file.open('rb') as file_handle:
            if imghdr.what(file):
                # copy normal images directly
                shutil.copy(file, destination_dir.name)
                continue
            else:
                # check if file is enc img or log file
                q = file_handle.read(300)
                breaked_data = q.split(b'_')
                img = (len(breaked_data[0]) == 3 or len(breaked_data[0]) == 4) and len(breaked_data) > 2

            t = File(file=file_handle)
            if img:
                # deocde image
                data, extension = helper_decrypt_image(t, key_map=key_map)
                image_name = file.name.split('.')
                image_name = f'{".".join(image_name[0:-1])}.{extension}'
                img_path = os.path.join(destination_dir.name, image_name)
                with open(img_path, "wb") as bfile:
                    bfile.write(data)

            else:
                # decode text
                try:
                    decrypt_log_file(t, key_map=key_map, dest_dir=destination_dir.name, file_name=file.name)
                except Exception as e:
                    print(e)
                    # for other remaining files
                    shutil.copy(file, destination_dir.name)


def handle_login(request, email, password):

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # if user with this email does not exists in db then sync db with ldap server
            sync_ldap_users()
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = None
    try:
        if user:
            ldap = LDAPBackend()
            ldap_authenticated_user = ldap.authenticate(request, username=user.username, password=password)
            if not ldap_authenticated_user:
                return False
            login(request, ldap_authenticated_user, backend='django.contrib.auth.backends.ModelBackend')
            return True
        return False
    except Exception as e:
        logger.debug(e)
        logger.error('some exception occurred while login')
        raise Exception


def sync_ldap_users():

    User = get_user_model()
    auth_kwargs = {
        User.USERNAME_FIELD: settings.LDAP_AUTH_CONNECTION_USERNAME,
        'password': settings.LDAP_AUTH_CONNECTION_PASSWORD
    }
    with ldap.connection(**auth_kwargs) as connection:
        if connection is None:
            raise Exception("Could not connect to LDAP server")
        for user in connection.iter_users():
            logger.debug("Synced {user}".format(user=user,))