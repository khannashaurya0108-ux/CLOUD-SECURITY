"""
SentinelAgent Proxy - AWS STS Temporary Token Requester
Integrates boto3 to assume task-scoped ephemeral roles with dynamically synthesized inline policies.
Falls back to high-fidelity mock STS in local sandbox/prototype modes.
"""

import os
import time
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


@dataclass
class TemporaryCredentials:
    """Ephemeral AWS credentials scoped to a single 30-second task."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: str
    assumed_role_arn: str
    is_mock: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "AccessKeyId": self.access_key_id,
            "SecretAccessKey": self.secret_access_key,
            "SessionToken": self.session_token,
            "Expiration": self.expiration,
            "AssumedRoleArn": self.assumed_role_arn,
            "IsMock": self.is_mock
        }


DEFAULT_BASE_ROLE_ARN = os.getenv(
    "SENTINEL_AWS_ROLE_ARN",
    "arn:aws:iam::123456789012:role/SentinelAgentTaskExecutionBaseRole"
)


def assume_task_scoped_role(
    policy_json: str,
    agent_id: str = "agent-primary",
    role_arn: str = DEFAULT_BASE_ROLE_ARN,
    duration_seconds: int = 900  # AWS STS minimum duration is 900s, but policy condition limits to 30s!
) -> TemporaryCredentials:
    """
    Invokes AWS STS AssumeRole with the synthesized inline policy document.
    The inline policy restricts the assumed role to ONLY the single action/resource
    specified, and the policy's DateLessThan condition kills access after 30 seconds.
    """
    session_name = f"sentinel-{agent_id[:16]}-{int(time.time())}"
    has_aws_creds = bool(os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))

    if BOTO3_AVAILABLE and has_aws_creds and not os.getenv("SENTINEL_FORCE_MOCK_STS"):
        try:
            sts_client = boto3.client("sts")
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                Policy=policy_json,
                DurationSeconds=max(900, duration_seconds)
            )
            creds = response["Credentials"]
            return TemporaryCredentials(
                access_key_id=creds["AccessKeyId"],
                secret_access_key=creds["SecretAccessKey"],
                session_token=creds["SessionToken"],
                expiration=creds["Expiration"].isoformat(),
                assumed_role_arn=response.get("AssumedRoleUser", {}).get("Arn", role_arn),
                is_mock=False
            )
        except (BotoCoreError, ClientError) as err:
            # If live AWS returns AccessDenied or MissingCreds in prototype mode, fall back to mock
            print(f"[Sentinel STS] Warning: Live AWS STS call failed ({err}). Falling back to local emulator.")

    # High-fidelity Local Prototype STS Credential Generator
    # Mimics AWS STS output exactly for local zero-trust demo evaluation
    now_utc = datetime.now(timezone.utc)
    expiration = now_utc + timedelta(seconds=30)
    fake_access_key = "ASIA" + secrets.token_hex(8).upper()
    fake_secret = secrets.token_urlsafe(32)
    fake_session_token = "IQoJb3JpZ2luX2VjE" + secrets.token_urlsafe(64)

    return TemporaryCredentials(
        access_key_id=fake_access_key,
        secret_access_key=fake_secret,
        session_token=fake_session_token,
        expiration=expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
        assumed_role_arn=f"arn:aws:sts::123456789012:assumed-role/SentinelAgentTaskExecutionBaseRole/{session_name}",
        is_mock=True
    )
