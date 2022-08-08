import base64
import json
import os
from typing import Optional, Union

import boto3
from botocore.exceptions import ClientError


class SecretHandler:
    def __init__(self, region_name: Optional[str] = None, profile: Optional[str] = None):
        # Create a Secrets Manager client
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None:
            assert region_name, "region name must be provided if running remotely"
            self._session = boto3.session.Session(region_name=region_name)
        else:
            assert profile, "profile must be provided if running locally"
            self._session = boto3.session.Session(profile_name=profile)
        self._client = self._session.client(service_name="secretsmanager")

    def get_secret(self, secret_name: str) -> Union[dict, bytes]:
        """
        If you need more information about configurations or implementing the sample code, visit the AWS docs:
        https://aws.amazon.com/developers/getting-started/python/

        Args:
            secret_name: the key-value pairs are stored in the secret manager under this name
            region_name: e.g. "eu-west-2"
            profile: for local run, you can provide the profile name (e.g. intriva)

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
