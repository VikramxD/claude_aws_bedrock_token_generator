"""
Core AWS credential generation functionality.

This module contains the pure business logic for generating
AWS session tokens, separated from CLI concerns.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from loguru import logger


class AWSCredentialManager:
    """
    Manages AWS credential generation and validation.
    """

    def __init__(self, access_key: str, secret_key: str, region: str = "us-east-1"):
        """
        Initialize the credential manager.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            region: AWS region
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def generate_session_token(self, duration_seconds: int = 129600) -> dict[str, Any] | None:
        """
        Generate temporary AWS session token.

        Args:
            duration_seconds: Token duration in seconds (default: 36 hours)

        Returns:
            dict: Session credentials or None if failed
        """
        try:
            logger.info(f"Generating session token for region: {self.region}")
            logger.info(f"Token duration: {duration_seconds} seconds ({duration_seconds/3600:.1f} hours)")

            # Create STS client
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region
            )

            # Get session token
            response = sts_client.get_session_token(DurationSeconds=duration_seconds)
            credentials = response['Credentials']

            logger.success("Session token generated successfully")
            logger.info(f"Token expires at: {credentials['Expiration']}")

            return {
                'access_key': credentials['AccessKeyId'],
                'secret_key': credentials['SecretAccessKey'],
                'token': credentials['SessionToken'],
                'expiration': credentials['Expiration']
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"AWS API error ({error_code}): {error_message}")
            return None

        except NoCredentialsError:
            logger.error("No valid AWS credentials found")
            return None

        except Exception as e:
            logger.error(f"Unexpected error generating session token: {e}")
            return None

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by calling STS GetCallerIdentity.

        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )

            identity = sts_client.get_caller_identity()
            logger.success("AWS credentials are valid")
            logger.info(f"Account ID: {identity['Account']}")
            logger.info(f"User ARN: {identity['Arn']}")
            return True

        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            return False


class ClaudeCodeFormatter:
    """
    Formats AWS credentials for Claude Code integration.
    """

    @staticmethod
    def format_export_command(credentials: dict[str, Any], region: str) -> str:
        """
        Format credentials as shell export command.

        Args:
            credentials: Session credentials dictionary
            region: AWS region

        Returns:
            str: Complete export command
        """
        aws_exports = (
            f"export AWS_ACCESS_KEY_ID={credentials['access_key']} && "
            f"export AWS_SECRET_ACCESS_KEY={credentials['secret_key']} && "
            f"export AWS_SESSION_TOKEN={credentials['token']}"
        )

        claude_exports = (
            f"export CLAUDE_CODE_USE_BEDROCK=1 && "
            f"export AWS_REGION={region} && "
            f"export ANTHROPIC_MODEL=us.anthropic.claude-opus-4-20250514-v1:0 && "
            f"export ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-4-sonnet-20250109-v1:0"
        )

        return f"{aws_exports} && {claude_exports}"

    @staticmethod
    def format_json_output(credentials: dict[str, Any], region: str) -> str:
        """
        Format credentials as JSON.

        Args:
            credentials: Session credentials dictionary
            region: AWS region

        Returns:
            str: JSON formatted credentials
        """
        import json

        output = {
            "aws_credentials": {
                "access_key_id": credentials['access_key'],
                "secret_access_key": credentials['secret_key'],
                "session_token": credentials['token'],
                "expiration": credentials['expiration'].isoformat()
            },
            "claude_config": {
                "use_bedrock": True,
                "region": region,
                "primary_model": "us.anthropic.claude-opus-4-20250514-v1:0",
                "fast_model": "us.anthropic.claude-4-sonnet-20250109-v1:0"
            }
        }

        return json.dumps(output, indent=2)
