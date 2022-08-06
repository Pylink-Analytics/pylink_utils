import base64
import json
import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError


def get_secret(secret_name: str, region_name: str, profile: Optional[str] = None) -> [dict, bytes]:
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

    # Create a Secrets Manager client
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None:
        session = boto3.session.Session()
    else:
        session = boto3.session.Session(profile_name=profile)
    client = session.client(service_name="secretsmanager", region_name=region_name)

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
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
