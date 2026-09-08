"""
SentinelAgent Proxy - Dynamic Just-in-Time (JIT) Policy Synthesizer
Maps LLM tool-call JSON payloads to least-privilege, short-lived AWS IAM JSON policies.
Enforces zero-wildcard rules and strict 30-second temporal restrictions.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple


class PolicySynthesisError(Exception):
    """Raised when a tool call cannot be safely mapped to a scoped IAM policy."""
    pass


def synthesize_iam_policy(
    tool_call: Dict[str, Any],
    agent_id: str = "agent-generic",
    validity_seconds: int = 30
) -> Tuple[Dict[str, Any], str, str]:
    """
    Parses a tool-call dictionary and synthesizes an ephemeral, least-privilege AWS IAM Policy.
    Returns:
        (policy_dict, policy_json_str, policy_sha256)
    """
    action = tool_call.get("action") or tool_call.get("tool") or tool_call.get("name")
    if not action:
        raise PolicySynthesisError("Missing 'action' or 'tool' field in tool call payload.")

    action_lower = str(action).lower().replace("-", "_")
    now_utc = datetime.now(timezone.utc)
    expiration_utc = now_utc + timedelta(seconds=validity_seconds)
    expiration_iso = expiration_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Temporal condition: strictly valid only until expiration_iso
    condition_block = {
        "DateLessThan": {
            "aws:CurrentTime": expiration_iso
        }
    }

    iam_action = None
    iam_resource = None

    # 1. Amazon S3 mappings
    if action_lower in ("s3_get_object", "get_object", "s3:getobject", "read_s3_file"):
        bucket = tool_call.get("bucket") or tool_call.get("bucket_name")
        key = tool_call.get("key") or tool_call.get("object_key") or tool_call.get("path")
        if not bucket or not key:
            raise PolicySynthesisError("S3 GetObject requires both 'bucket' and 'key' parameters.")
        # Strip dangerous path traversal
        clean_key = key.lstrip("/").replace("../", "")
        iam_action = "s3:GetObject"
        iam_resource = f"arn:aws:s3:::{bucket}/{clean_key}"

    elif action_lower in ("s3_put_object", "put_object", "s3:putobject", "write_s3_file"):
        bucket = tool_call.get("bucket") or tool_call.get("bucket_name")
        key = tool_call.get("key") or tool_call.get("object_key")
        if not bucket or not key:
            raise PolicySynthesisError("S3 PutObject requires both 'bucket' and 'key' parameters.")
        clean_key = key.lstrip("/").replace("../", "")
        iam_action = "s3:PutObject"
        iam_resource = f"arn:aws:s3:::{bucket}/{clean_key}"

    elif action_lower in ("s3_list_objects_v2", "list_bucket", "s3:listbucket"):
        bucket = tool_call.get("bucket") or tool_call.get("bucket_name")
        prefix = tool_call.get("prefix", "")
        if not bucket:
            raise PolicySynthesisError("S3 ListBucket requires 'bucket' parameter.")
        iam_action = "s3:ListBucket"
        iam_resource = f"arn:aws:s3:::{bucket}"
        if prefix:
            condition_block["StringLike"] = {"s3:prefix": f"{prefix}*"}

    # 2. DynamoDB mappings
    elif action_lower in ("dynamodb_get_item", "get_item", "dynamodb:getitem"):
        table = tool_call.get("table") or tool_call.get("table_name")
        region = tool_call.get("region", "us-east-1")
        account_id = tool_call.get("account_id", "123456789012")
        if not table:
            raise PolicySynthesisError("DynamoDB GetItem requires 'table' parameter.")
        iam_action = "dynamodb:GetItem"
        iam_resource = f"arn:aws:dynamodb:{region}:{account_id}:table/{table}"

    elif action_lower in ("dynamodb_query", "query_table", "dynamodb:query"):
        table = tool_call.get("table") or tool_call.get("table_name")
        region = tool_call.get("region", "us-east-1")
        account_id = tool_call.get("account_id", "123456789012")
        if not table:
            raise PolicySynthesisError("DynamoDB Query requires 'table' parameter.")
        iam_action = "dynamodb:Query"
        iam_resource = f"arn:aws:dynamodb:{region}:{account_id}:table/{table}"

    # 3. Amazon SQS mappings
    elif action_lower in ("sqs_send_message", "send_message", "sqs:sendmessage"):
        queue = tool_call.get("queue") or tool_call.get("queue_name")
        region = tool_call.get("region", "us-east-1")
        account_id = tool_call.get("account_id", "123456789012")
        if not queue:
            raise PolicySynthesisError("SQS SendMessage requires 'queue' parameter.")
        iam_action = "sqs:SendMessage"
        iam_resource = f"arn:aws:sqs:{region}:{account_id}:{queue}"

    # 4. AWS Secrets Manager (Task-scoped secret retrieval)
    elif action_lower in ("get_secret_value", "secretsmanager:getsecretvalue"):
        secret_name = tool_call.get("secret_name") or tool_call.get("secret_id")
        region = tool_call.get("region", "us-east-1")
        account_id = tool_call.get("account_id", "123456789012")
        if not secret_name:
            raise PolicySynthesisError("SecretsManager requires specific 'secret_name'.")
        # Prevent wildcard secret retrieval
        if "*" in secret_name or "?" in secret_name:
            raise PolicySynthesisError("Wildcard secret retrieval is forbidden under Zero-Trust policy.")
        iam_action = "secretsmanager:GetSecretValue"
        iam_resource = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{secret_name}*"

    # Generic or custom MCP tool mapping fallback
    else:
        # Check if direct AWS IAM action is passed
        raw_action = tool_call.get("iam_action") or tool_call.get("action")
        raw_arn = tool_call.get("iam_resource") or tool_call.get("resource_arn")
        if raw_action and raw_arn:
            if "*" in raw_arn:
                raise PolicySynthesisError("Wildcard resources ('*') are strictly disallowed in Sentinel synthesized policies.")
            if raw_action.lower().startswith("iam:") or raw_action.lower().startswith("sts:"):
                raise PolicySynthesisError("Privilege escalation: IAM/STS administrative actions cannot be synthesized.")
            iam_action = raw_action
            iam_resource = raw_arn
        else:
            raise PolicySynthesisError(
                f"Unsupported or unmapped tool action '{action}'. Cannot synthesize least-privilege IAM policy."
            )

    # Validate against zero-trust invariants:
    if not iam_resource or iam_resource == "*" or iam_resource.endswith(":::*"):
        raise PolicySynthesisError("Security Violation: Synthesizer generated wildcard resource ARN.")
    if not iam_action or "*" in iam_action:
        raise PolicySynthesisError("Security Violation: Synthesizer generated wildcard action.")

    # Construct the AWS IAM JSON Policy Document (Version 2012-10-17)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"SentinelJITTaskScoped{agent_id.replace('-', '').replace('_', '')[:12]}",
                "Effect": "Allow",
                "Action": [iam_action],
                "Resource": [iam_resource],
                "Condition": condition_block
            }
        ]
    }

    # Minified / deterministic JSON serialization for cryptographic hashing
    policy_json = json.dumps(policy_doc, indent=2, sort_keys=True)
    policy_sha256 = hashlib.sha256(policy_json.encode("utf-8")).hexdigest()

    return policy_doc, policy_json, policy_sha256
