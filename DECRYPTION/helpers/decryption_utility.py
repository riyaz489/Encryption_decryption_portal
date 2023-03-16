import ast
import os
import re
from urllib.parse import unquote_to_bytes
from django.conf import settings
from Crypto.Cipher import AES
from django.core.files.temp import NamedTemporaryFile

from helpers.key_util import get_encryption_key, get_Key_encryption_key, unwrap_dek


def decrypt_log_file(file, key_map, dest_dir=None, file_name=None):
    key_val_dict = {}
    encrypted_text_set = []

    # find all encrypted text
    # reading line by line to avoid server failure in case of large files
    for line in file:
        line = line.decode("utf-8")
        encrypted_text_set.extend(re.findall("{{(.*?)}}", line))

    encrypted_text_set = set(encrypted_text_set)

    # creating map for encrypted and decrypted values to reduce API calls
    for encrypted_text in encrypted_text_set:
        decoded_text, is_valid_cipher = helper_decrypt_text(encrypted_text, key_map)
        if is_valid_cipher:
            key_val_dict[encrypted_text] = decoded_text.decode("utf-8")

    final_file = os.path.join(dest_dir, file_name) if dest_dir else NamedTemporaryFile(suffix='.txt').name
    # replacing text in file
    with open(final_file, 'w+')as d:
        for line in file:
            result = line.decode("utf-8")
            for k, v in key_val_dict.items():
                result = result.replace("{{" + k + "}}", v)
            d.write(result)
    return final_file


def helper_decrypt_text(cipher_text, key_map):
    try:
        splitted_data = cipher_text.split('_')
        version = splitted_data.pop(-1)
        encrypted_data = "_".join(splitted_data)
        encrypted_data = unquote_to_bytes(encrypted_data)
        iv = encrypted_data[0:16]
        encrypted_data = encrypted_data[16:]
        dek = None

        if version in key_map:
            dek = key_map[version]
        else:
            key = get_encryption_key(settings.VAULT_NAME, settings.SECRET_NAME, version)
            kek = get_Key_encryption_key(settings.VAULT_NAME, settings.KEY_NAME)
            # unwrap dek
            dek = unwrap_dek(dek=ast.literal_eval(key.value), kek=kek)
            key_map[version] = dek

        result = AES.new(dek, AES.MODE_CFB, iv)
        return result.decrypt(encrypted_data), True
    except:
        return "not a valid cipher text", False


def helper_decrypt_image(img, key_map):

    extension = ""

    x = b''
    iv = None
    key_version = ""
    flag = True
    for chunks in img.chunks():
        # DEFAULT_CHUNK_SIZE = 64 * 2 ** 10
        x += chunks

        if flag:
            # fetching image extension
            extension = x.split(b'_')[0].decode('utf-8')
            # fetching key version
            key_version = x.split(b'_')[1].decode('utf-8')
            # removing key version and image extension from cipher data
            x = b"_".join(x.split(b'_')[2:])
            iv = x[0:16]
            flag = False
            x = x[16:]

    if key_version not in key_map:
        key = get_encryption_key(settings.VAULT_NAME, settings.SECRET_NAME, key_version)
        kek = get_Key_encryption_key(settings.VAULT_NAME, settings.KEY_NAME)
        dek = unwrap_dek(kek=kek, dek=ast.literal_eval(key.value))
        key_map[key_version] = dek

    cfb_decipher = AES.new(key_map[key_version], AES.MODE_CFB, iv)
    plain_data = cfb_decipher.decrypt(x)
    return plain_data, extension
