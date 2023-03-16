import ast
import os
import time
import yaml

from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.keyvault.keys import KeyVaultKey, KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
from azure.keyvault.secrets import SecretClient, KeyVaultSecret
from Crypto import Random
from Crypto.Cipher import AES
from enum import Enum
from logging import getLogger
from urllib.parse import quote_from_bytes
from typing import Optional, Any

logger = getLogger(__name__)

KWARGS_AZURE_KEYS = ('azure_client_id', 'azure_tenant_id', 'azure_client_secret', 'key_vault', 'key_name', 'kek_name')


class NotSetupException(Exception):
    """Raised when functions are called without setting up EncryptText class."""

    pass


class DEK:
    """
    model class to contains data encryption key value and properties.
    """

    def __init__(self, dek: bytes, version: str):
        """
        this method is used to initialize DEK class object.

        Args:
            dek (bytes): data encryption key.
            version (str): version of data encryption key.
        """
        self.dek = dek
        self.version = version


class AzureConstants(Enum):
    VAULT_NAME = 'VAULT_NAME'
    SECRET_NAME = 'SECRET_NAME'
    AZURE_CLIENT_ID = 'AZURE_CLIENT_ID'
    AZURE_CLIENT_SECRET = "AZURE_CLIENT_SECRET"
    AZURE_TENANT_ID = "AZURE_TENANT_ID"
    KEY_NAME = 'KEY_NAME'


class ExpiryProperty(object):
    """
    This class is used to create cached properties.
    default TTl is 10 minutes.
    """
    def __init__(self, expires_time: int = 10*60):
        """
        Set expires time in seconds for current Key property.

        Args:
            expires_time (int): time to live in seconds for key property.

        Returns:
            None
        """
        self._key = None
        self.expires_time = expires_time
        self.created = None

    @property
    def key(self):
        """
        Setter for Key property.
        """
        current_time = time.time()

        # if value is not set yet then return None
        if self.created is None:
            return None

        if current_time - self.created > self.expires_time:
            self._key = None
        return self._key

    @key.setter
    def key(self, value):
        """
        Getter for Key property.
        """
        self._key = value
        self.created = time.time()


class EncryptText:
    """
    This class is used to Encrypt text data.
    default TTl for encryption key is 10 minutes.
    """
    _encryption_key = None

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
    def setup_key_vault(cls, secret_yml_file_path: Optional[str] = None,
                        secret_ttl: Optional[int] = 10*60,
                        confidential: Optional[Any] = None,
                        **kwargs: str) -> None:
        """
        This method is used to set secrets which is required by Azure Key vault client.
        Note: only one type of argument is required for setting up azure key-vault
                secret_yml_file_path/confidential/kwargs
        Args:
            secret_yml_file_path (Optional[str]): The yaml path, from which we fetch azure secrets.
            secret_ttl (Optional[int]): time in seconds, for which encryption key is stored in memory.
                                        (to reduce Azure API calls.)
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
            key_vault (str): Azure Key vault name.
            key_name (str): Azure Key vault Secret name.
            kek_name (str): Azure key vault key name.

        Returns:
            None.
        """
        cls._encryption_key = ExpiryProperty(expires_time=secret_ttl)

        if all(key in kwargs for key in KWARGS_AZURE_KEYS):
            logger.info(f"Setting up environment variables for Azure client ")
            os.environ[str(AzureConstants.AZURE_CLIENT_ID.value)] = kwargs.pop('azure_client_id')
            os.environ[str(AzureConstants.AZURE_TENANT_ID.value)] = kwargs.pop('azure_tenant_id')
            os.environ[str(AzureConstants.AZURE_CLIENT_SECRET.value)] = kwargs.pop('azure_client_secret')
            os.environ[str(AzureConstants.VAULT_NAME.value)] = kwargs.pop('key_vault')
            os.environ[str(AzureConstants.SECRET_NAME.value)] = kwargs.pop('key_name')
            os.environ[str(AzureConstants.KEY_NAME.value)] = kwargs.pop('kek_name')

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
    def encrypt(cls, data: str, key_vault: Optional[str] = None,
                key_name: Optional[str] = None,
                kek_name: Optional[str] = None) -> str:
        """
        This method is used ot encrypt text data.

        Args:
            data (str): This argument contains string input data.
            key_vault (Optional[str]): key vault name.
            key_name (Optional[str]): key vault secret name.
            kek_name (Optional[str]): key vault key name.

        Returns:
            Encrypted data in string.

         Raises:
            NotSetupException: If this method is called before calling :func:`setup_key_vault`.
        """

        if cls._encryption_key is None:
            raise NotSetupException('Key Vault setup is not done for this class')
        iv = Random.new().read(AES.block_size)
        bytes_data = bytes(data, 'utf-8')

        try:
            if cls._encryption_key.key is None:
                key_vault = os.getenv(str(AzureConstants.VAULT_NAME.value)) if key_vault is None else key_vault
                key_name = os.getenv(str(AzureConstants.SECRET_NAME.value)) if key_name is None else key_name
                kek_name = os.getenv(str(AzureConstants.KEY_NAME.value)) if kek_name is None else kek_name
                wrapped_dek = cls._get_encryption_key(key_vault=key_vault, key_name=key_name)
                dek = cls._unwrap_dek(key_name=kek_name,
                                      key_vault=key_vault,
                                      dek=ast.literal_eval(wrapped_dek.value))
                cls._encryption_key.key = DEK(dek=dek, version=wrapped_dek.properties.version)
            cfb_cipher = AES.new(cls._encryption_key.key.dek, AES.MODE_CFB, iv)
            enc_data = cfb_cipher.encrypt(bytes_data)
            # preforming url encoding to avoid spaces
            final_cipher = quote_from_bytes(iv+enc_data)
            return "{{"+f'{str(final_cipher)}_{cls._encryption_key.key.version}'+"}}"
        except Exception:
            logger.exception("Error occurred while encrypting data ", exc_info=True)
