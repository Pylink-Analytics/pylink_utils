import os
from abc import ABC
from typing import Optional

import boto3


class SessionABC(ABC):
    def __init__(self, region_name: Optional[str] = None, profile_name: Optional[str] = None):
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None:
            assert region_name, "region name must be provided if running remotely"
            self._session = boto3.session.Session(region_name=region_name)
        else:
            assert profile_name, "profile_name must be provided if running locally"
            self._session = boto3.session.Session(profile_name=profile_name)
