#  ------------------------------- START OF LICENSE NOTICE -----------------------------
#  Copyright (c) 2019 Soroco Private Limited. All rights reserved.
#
#  NO WARRANTY. THE PRODUCT IS PROVIDED BY SOROCO "AS IS" AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SOROCO BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE PRODUCT, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  -------------------------------- END OF LICENSE NOTICE ------------------------------
"""For capturing images of the screen."""
import ast
import enum
import io
import os
import yaml

from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.keyvault.keys import KeyVaultKey, KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
from azure.keyvault.secrets import SecretClient, KeyVaultSecret
from Crypto.Cipher import AES
from Crypto import Random
from datetime import datetime
from exceptions import (
    CaptureFailedException,
    InvalidSubdirPathException,
    MultipleSetupException,
    NotSetupException,
)
from logging import getLogger
from pathlib import Path
from PIL import ImageGrab
from PIL.Image import Image
from typing import List, Optional, Union, Any

logger = getLogger(__name__)


class AzureConstants(enum.Enum):
    VAULT_NAME = 'VAULT_NAME'
    SECRET_NAME = 'SECRET_NAME'
    AZURE_CLIENT_ID = 'AZURE_CLIENT_ID'
    AZURE_CLIENT_SECRET = "AZURE_CLIENT_SECRET"
    AZURE_TENANT_ID = "AZURE_TENANT_ID"
    KEY_NAME = "KEY_NAME"


class Screenshot:
    """A class to help capture images of the screen."""

    _dir_path: Optional[Path] = None
    _setup_done = False

    @classmethod
    def setup(cls, screenshot_dir_path: Path, confidential: Any, secret_yml_file_path: str = None, **kwargs: str) -> None:
        """
        Configure Screenshot class to create screenshots in the given directory.
        This function creates the directory if it does not already exist.

        Note: only one type of argument is required for setting up azure key-vault
        secret_yml_file_path / confidential / kwargs

        Args:
            screenshot_dir_path (Path): The directory to store screenshots in.
            secret_yml_file_path (str): The yaml path, from which we fetch azure secrets.
            confidential (Optional[Any]): Automation Confidential object for current cc which contains config for
                                            key vault.
                                            sample config of key_vault:-
                                            KEY_VAULT_CONFIG= {
                                                AZURE_CLIENT_ID: secret,
                                                AZURE_CLIENT_SECRET: secret,
                                                AZURE_TENANT_ID: secret,
                                                VAULT_NAME: vault name contains KEK and DEK.,
                                                SECRET_NAME: DEK secret name,
                                                KEY_NAME: KEK key name
                                            }

        Keyword Args:
            azure_client_id (str): Azure client Id with azure-vault key permissions.
            azure_tenant_id (str): Azure tenant Id with azure-vault key permissions.
            azure_client_secret (str): Azure client key.

        Returns:
            None.

        Raises:
            MultipleSetupException: If this function is called more than once without
                calling :func:`teardown`.
        """
        if cls._setup_done:
            raise MultipleSetupException()

        cls._dir_path = screenshot_dir_path
        cls._dir_path.mkdir(parents=True, exist_ok=True)

        # Resolution cannot be done until it folder is created
        cls._dir_path = cls._dir_path.resolve()
        logger.info(f"Setting up screenshot with directory: {cls._dir_path}")

        # population environment variables
        if all(key in kwargs for key in ('azure_client_id', 'azure_tenant_id', 'azure_client_secret')):
            logger.info(f"Setting up environment variables for Azure client ")
            os.environ[str(AzureConstants.AZURE_CLIENT_ID.value)] = kwargs.pop('azure_client_id')
            os.environ[str(AzureConstants.AZURE_TENANT_ID.value)] = kwargs.pop('azure_tenant_id')
            os.environ[str(AzureConstants.AZURE_CLIENT_SECRET.value)] = kwargs.pop('azure_client_secret')
        elif confidential:
            logger.info(f"Setting up environment variables for Azure client from confidential service ")
            azure_config: dict = confidential.getitem('KEY_VAULT_CONFIG')
            os.environ[str(AzureConstants.AZURE_CLIENT_ID.value)] = azure_config.get('AZURE_CLIENT_ID')
            os.environ[str(AzureConstants.AZURE_TENANT_ID.value)] = azure_config.get('AZURE_TENANT_ID')
            os.environ[str(AzureConstants.AZURE_CLIENT_SECRET.value)] = azure_config.get('AZURE_CLIENT_SECRET')
            os.environ[str(AzureConstants.VAULT_NAME.value)] = azure_config.get('VAULT_NAME')
            os.environ[str(AzureConstants.SECRET_NAME.value)] = azure_config.get('SECRET_NAME')
            os.environ[str(AzureConstants.KEY_NAME.value)] = azure_config.get('KEY_NAME')
        elif secret_yml_file_path:
            logger.info(f"Setting up environment variables for Azure client from Yaml file")
            cls._set_secrets_from_yaml(secret_yml_file_path)

        cls._setup_done = True

    @classmethod
    def _set_secrets_from_yaml(cls, file_path: str) -> None:
        """
        Set Azure secrets into environment variables from secret yaml file.
        Args:
            file_path (str): The yaml path, from which we fetch azure secrets.
        Returns:
            None
        """
        with open(file_path, 'r') as secret:
            try:
                data = yaml.safe_load_all(secret).__next__()
                for key, value in data.items():
                    os.environ[key] = value

            except yaml.YAMLError:
                logger.error('some error occurred while setting environment variables for Azure Client')

    @classmethod
    def teardown(cls) -> None:
        """
        Reset configuration of Screenshot class.

        Once this function has been called, :func:`setup` needs to be called before
        using :func:`capture` or :func:`get_local_files` method.

        Returns:
            None
        """
        cls._dir_path = None
        cls._setup_done = False

    @classmethod
    def _get_kek(cls, key_vault: str, key_name: str) -> KeyVaultKey:
        """
        Get the latest version encryption key from Azure Vault.

        Args:
            key_vault (str): key_vault name.
            key_name (str): key name.
            variables.

        Returns:
             Azure KeyVaultSecret object which contains key and its properties.
        """
        logger.info('fetching key from azure key vault.')
        key_vault_uri = "https://" + key_vault + ".vault.azure.net"
        client = KeyClient(vault_url=key_vault_uri, credential=DefaultAzureCredential())
        try:
            return client.get_key(key_name)
        except ClientAuthenticationError:
            logger.error('\nAZURE_CLIENT_ID ,AZURE_CLIENT_SECRET & AZURE_TENANT_ID environment variables are not set\n'
                         'note: you can create new principal to get these values with the help of this command:\n'
                         '`az ad sp create-for-rbac --name <principal_name> --skip-assignment`\n'
                         'to give vault permission to above principal use this command:\n'
                         '`az keyvault set-policy --name <key-vault-name> --spn <AZURE_CLIENT_ID> '
                         '--secret-permissions get `\n'
                         )

    @classmethod
    def _unwrap_dek(cls, key_name: str, key_vault: str,  dek: bytes) -> bytes:
        """
        Unwrap the DEK.

        Args:
            key_name(str): key encryption key name.
            key_vault(str): key vault name.
            dek(bytes): data encryption key.

        Returns:
            unwrapped data encryption key in bytes.
        """
        kek = cls._get_kek(key_name=key_name, key_vault=key_vault)
        crypto_client = CryptographyClient(kek, credential=DefaultAzureCredential())
        return crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep, dek).plaintext

    @classmethod
    def _get_encryption_key(cls, key_vault: str, key_name: str) -> KeyVaultSecret:
        """
        Get the latest version encryption key from Azure Vault.

        Args:
            key_vault (str): key_vault name.
            key_name (str): key name.
            variables.

        Returns:
             Azure KeyVaultSecret object which contains key and its properties.
        """
        logger.info('fetching key from azure key vault.')
        key_vault_uri = "https://" + key_vault + ".vault.azure.net"
        client = SecretClient(vault_url=key_vault_uri, credential=DefaultAzureCredential())
        try:
            return client.get_secret(key_name)
        except ClientAuthenticationError:
            logger.error('\nAZURE_CLIENT_ID ,AZURE_CLIENT_SECRET & AZURE_TENANT_ID environment variables are not set\n'
                         'note: you can create new principal to get these values with the help of this command:\n'
                         '`az ad sp create-for-rbac --name <principal_name> --skip-assignment`\n'
                         'to give vault permission to above principal use this command:\n'
                         '`az keyvault set-policy --name <key-vault-name> --spn <AZURE_CLIENT_ID> '
                         '--secret-permissions get `\n'
                         )

    @classmethod
    def _encrypt_image(cls, image: Image, encryption_key: bytes, key_version: str) -> bytes:
        """
        This function is used to encrypt image with AES algorithm(key size = 16 bytes).

        Args
            image (Image): PIL image object.
            encryption_key (bytes): 16 bytes of AES algorithm encryption key.
            key_version (str): encryption key versioin.

        Returns:
            bytes of cipher data.
        """
        image_format = 'PNG'
        logger.info("converting images into bytes array")
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        image_bytes_data = img_byte_arr.getvalue()

        iv = Random.new().read(AES.block_size)
        logger.info("encrypting image")
        cfb_cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
        enc_data = cfb_cipher.encrypt(image_bytes_data)
        logger.info("encrypted image")
        # adding iv to the cipher data (we can make iv public)
        enc_data = iv + enc_data
        # preserving original extension of file by adding it encrypted data
        # and adding encryption key version.
        return f"{image_format}_{key_version}_".encode('utf-8')+enc_data

    @classmethod
    def capture(
        cls,
        key_vault: Optional[str] = None,
        key_name: Optional[str] = None,
        kek_name: Optional[str] = None,
        prefix: Optional[str] = None,
        subdir_path: Optional[Union[str, Path]] = None,
        raise_exception: bool = False,
    ) -> None:
        """
        Take a screenshot of the current screen and save it.

        The screenshot will be stored in ``screenshot_dir_path``. If subdir_path is
        given then it will be stored in that subdirectory.

        The name of the file will be ``<prefix>-<timestamp>-<key_version>.enc`` if prefix is given
        else it will be ``<timestamp>-<key_version>.enc``

        Args:
            key_vault (Optional[str]): optional key_vault name, if its None then we take it from environment variables
            (VAULT_NAME).
            key_name (Optional[str]): optional key name, if its None then we take it from environment (SECRET_NAME).
            variables.
            kek_name (Optional[str]): KEK name, if its None then we take it from environment (KEY_NAME).
            prefix (Optional[str]): optional prefix of the screenshot file name.
            subdir_path (Optional[Union[str, Path]]): If given the screenshot will be
                stored in the subdirectory. If ``subdir_path`` does not exist, it will
                be created.
            raise_exception (bool): If false, suppresses :any:`CaptureFailedException`.

        Returns:
            None.

        Raises:
            NotSetupException: If this method is called before calling :func:`setup`.
            CaptureFailedException: If something went wrong while capturing screenshot.
            InvalidSubdirPathException: If the given subdir path is not a subdirectory
                of the directory that Screenshot was setup with.
        """
        if not cls._setup_done:
            raise NotSetupException()

        key_vault = os.getenv(str(AzureConstants.VAULT_NAME.value)) if key_vault is None else key_vault
        key_name = os.getenv(str(AzureConstants.SECRET_NAME.value)) if key_name is None else key_name
        kek_name = os.getenv(str(AzureConstants.KEY_NAME.value)) if kek_name is None else kek_name

        encryption_key = cls._get_encryption_key(key_name=key_name, key_vault=key_vault)
        data_encryption_key = cls._unwrap_dek(dek=ast.literal_eval(encryption_key.value),
                                              key_name=kek_name,
                                              key_vault=key_vault)
        file_path = cls._get_file_path(prefix, subdir_path)

        try:
            logger.info(f"Taking screenshot, encrypting it and saving it in file: {file_path}")
            image = ImageGrab.grab()
            encrypted_data = cls._encrypt_image(
                image=image,
                encryption_key=data_encryption_key,
                key_version=encryption_key.properties.version)
            with open(file_path, "wb") as output_file:
                output_file.write(encrypted_data)

        except Exception as e:
            if raise_exception:
                raise CaptureFailedException() from e
            logger.exception(
                f"Error occurred while taking screenshot and saving it at {file_path}",
                exc_info=True,
            )

    @classmethod
    def _get_file_path(cls, prefix: Optional[str], subdir_path: Optional[Union[Path, str]]) -> Path:
        """
        Return file path where screenshot is to be stored.

        The name of the file will be <prefix>-<timestamp>-<key_version>.enc if prefix is given else it
        will be <timestamp>-<key_version>.enc

        Args:
            prefix (Optional[str]): optional prefix of the screenshot file name.
            subdir_path (Optional[Union[Path, str]]): If given the screenshot will be stored in the subdirectory.
                If subdir_path does not exist, it will be created.

        Returns:
            File path where screenshot is to be stored.

        Raises:
            InvalidSubdirPathException: If the given subdir path is not a subdirectory
                of the directory that Screenshot was setup with.
        """
        current_time = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        file_name = (
            f"{current_time}.enc" if prefix is None else f"{prefix}-{current_time}.enc"
        )

        if not subdir_path:
            return cls._dir_path / file_name

        if isinstance(subdir_path, str):
            subdir_path = Path(subdir_path)

        absolute_subdir_path = (cls._dir_path / subdir_path).resolve()

        if cls._dir_path not in absolute_subdir_path.parents:
            raise InvalidSubdirPathException(
                f"{absolute_subdir_path} is not a sub-directory of {cls._dir_path}"
            )

        absolute_subdir_path.mkdir(parents=True, exist_ok=True)
        return absolute_subdir_path / file_name

    @classmethod
    def get_local_files(cls, glob_pattern: str) -> List[str]:
        """
        Return all files that match given glob pattern in the screenshot directory.

        Args:
            glob_pattern (str): Any glob pattern.

        Returns:
            List[str]: List of absolute file paths of each screenshot file that matched.

        Raises:
            NotSetupException: If this method is called before calling :func:`setup`.
        """
        if not cls._setup_done:
            raise NotSetupException()

        return [
            str(path.resolve())
            for path in cls._dir_path.glob(glob_pattern)
            if path.is_file()
        ]
