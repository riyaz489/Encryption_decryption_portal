from azure.identity import DefaultAzureCredential
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
from azure.core.exceptions import ClientAuthenticationError
from azure.keyvault.secrets import SecretClient, KeyVaultSecret
from azure.keyvault.keys import KeyVaultKey, KeyClient
from logging import getLogger


logger = getLogger(__name__)


def get_encryption_key(key_vault: str, key_name: str, version: str) -> KeyVaultSecret:
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
        result = client.get_secret(name=key_name, version=version)
        return result
    except ClientAuthenticationError:

        logger.error('\nAZURE_CLIENT_ID ,AZURE_CLIENT_SECRET & AZURE_TENANT_ID environment variables are not set\n'
                     'note: you can create new principal to get these values with the help of this command:\n'
                     '`az ad sp create-for-rbac --name <principal_name> --skip-assignment`\n'
                     'to give vault permission to above principal use this command:\n'
                     '`az keyvault set-policy --name <key-vault-name> --spn <AZURE_CLIENT_ID> '
                     '--secret-permissions get `\n'
                     )


def get_Key_encryption_key(key_vault: str, key_name: str) -> KeyVaultKey:
    """
    Get the latest version encryption key from Azure Vault.

    Args:
        key_vault (str): key_vault name.
        key_name (str): key name.
        variables.

    Returns:
         Azure KeyVaultKey object which contains key and its properties.
    """
    logger.info('fetching key from azure key vault.')
    key_vault_uri = "https://" + key_vault + ".vault.azure.net"
    client = KeyClient(vault_url=key_vault_uri, credential=DefaultAzureCredential())
    try:
        result = client.get_key(name=key_name)
        return result
    except ClientAuthenticationError:

        logger.error('\nAZURE_CLIENT_ID ,AZURE_CLIENT_SECRET & AZURE_TENANT_ID environment variables are not set\n'
                     'note: you can create new principal to get these values with the help of this command:\n'
                     '`az ad sp create-for-rbac --name <principal_name> --skip-assignment`\n'
                     'to give vault permission to above principal use this command:\n'
                     '`az keyvault set-policy --name <key-vault-name> --spn <AZURE_CLIENT_ID> '
                     '--secret-permissions get `\n'
                     )


def unwrap_dek(kek: KeyVaultKey, dek: bytes) -> bytes:
    """
    Unwrap the DEK.

    Args:
        kek(KeyVaultKey): key encryption key .
        dek(bytes): data encryption key.

    Returns:
        unwrapped data encryption key in bytes.
    """

    crypto_client = CryptographyClient(kek, credential=DefaultAzureCredential())
    return crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep, dek).plaintext

