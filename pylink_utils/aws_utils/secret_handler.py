import base64
import json
from typing import Optional, Union

from botocore.exceptions import ClientError

from . import SessionABC


class SecretHandler(SessionABC):
    def __init__(self, region_name: Optional[str] = None, profile_name: Optional[str] = None):
        # Create a Secrets Manager client
        super().__init__(region_name=region_name, profile_name=profile_name)
        self._client = self._session.client(service_name="secretsmanager")

    def get_secret(self, secret_name: str) -> Union[dict, bytes]:
        """
        If you need more information about configurations or implementing the sample code, visit the AWS docs:
        https://aws.amazon.com/developers/getting-started/python/

        Args:
            secret_name: the key-value pairs are stored in the secret manager under this name
            region_name: e.g. "eu-west-2"
            profile_name: for local run, you can provide the profile_name name (e.g. intriva)

        Returns:
            secret: this stores all the key-value pairs
            decoded_binary_secret
        """

        try:
            get_secret_value_response = self._client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            raise e
        else:
            # Decrypts secret using the associated KMS key.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if "SecretString" in get_secret_value_response:
                secret = get_secret_value_response["SecretString"]
                return json.loads(secret)
            else:
                decoded_binary_secret = base64.b64decode(get_secret_value_response["SecretBinary"])
                return decoded_binary_secret
