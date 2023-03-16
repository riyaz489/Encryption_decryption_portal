############### text encryption ##########################

from log_encryption import EncryptText

EncryptText.setup_key_vault(secret_yml_file_path=r"C:\Users\RiyazuddinKhan\PycharmProjects\img_encyption\secrets.yaml")
result = EncryptText.encrypt(data="hello")
print(result)
print(type(result))
result = EncryptText.encrypt(data="hi")
print(result)
print(type(result))


########### image encryption #############################

# from screenshot import Screenshot
#
# Screenshot.setup(Path(r'C:\Users\RiyazuddinKhan\PycharmProjects\img_encyption\tmp'), secret_yml_file_path=r'C:\Users\RiyazuddinKhan\PycharmProjects\img_encyption\secrets.yaml')
#
# Screenshot.capture()
#
# Screenshot.teardown()