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
            logger.info(f"🌍 Generating session token for region: {self.region}")
            logger.info(f"⏰ Token duration: {duration_seconds} seconds ({duration_seconds/3600:.1f} hours)")

            # Validate duration (AWS STS limits)
            if duration_seconds < 900:  # 15 minutes minimum
                logger.warning(f"⚠️  Duration {duration_seconds}s is below AWS minimum (900s). Using 900s.")
                duration_seconds = 900
            elif duration_seconds > 129600:  # 36 hours maximum
                logger.warning(f"⚠️  Duration {duration_seconds}s exceeds AWS maximum (129600s). Using 129600s.")
                duration_seconds = 129600

            # Create STS client
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region
            )

            # Get session token
            logger.debug("🔐 Requesting session token from AWS STS...")
            response = sts_client.get_session_token(DurationSeconds=duration_seconds)
            credentials = response['Credentials']

            logger.success("✅ Session token generated successfully")
            logger.info(f"🕒 Token expires at: {credentials['Expiration']}")

            return {
                'access_key': credentials['AccessKeyId'],
                'secret_key': credentials['SecretAccessKey'],
                'token': credentials['SessionToken'],
                'expiration': credentials['Expiration']
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Provide more helpful error messages
            if error_code == 'InvalidUserID.NotFound':
                logger.error(f"❌ AWS user not found. Check your AWS_ACCESS_KEY_ID.")
            elif error_code == 'SignatureDoesNotMatch':
                logger.error(f"❌ Invalid AWS credentials. Check your AWS_SECRET_ACCESS_KEY.")
            elif error_code == 'TokenRefreshRequired':
                logger.error(f"❌ AWS credentials have expired. Please refresh your credentials.")
            elif error_code == 'AccessDenied':
                logger.error(f"❌ Access denied. Your AWS user may not have permission to call sts:GetSessionToken.")
            else:
                logger.error(f"❌ AWS API error ({error_code}): {error_message}")
            
            return None

        except NoCredentialsError:
            logger.error("❌ No valid AWS credentials found")
            return None

        except Exception as e:
            logger.error(f"❌ Unexpected error generating session token: {e}")
            return None

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by calling STS GetCallerIdentity.

        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            logger.debug("🔍 Creating STS client for validation...")
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )

            logger.debug("🔐 Calling GetCallerIdentity...")
            identity = sts_client.get_caller_identity()
            
            logger.success("✅ AWS credentials are valid")
            logger.info(f"🏢 Account ID: {identity['Account']}")
            logger.info(f"👤 User ARN: {identity['Arn']}")
            
            # Extract and log user information
            arn_parts = identity['Arn'].split(':')
            if len(arn_parts) >= 6:
                user_info = arn_parts[5]
                if '/' in user_info:
                    user_type, user_name = user_info.split('/', 1)
                    logger.info(f"🔑 User Type: {user_type}, Name: {user_name}")
            
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'InvalidUserID.NotFound':
                logger.error(f"❌ AWS user not found. Check your AWS_ACCESS_KEY_ID.")
            elif error_code == 'SignatureDoesNotMatch':
                logger.error(f"❌ Invalid AWS credentials. Check your AWS_SECRET_ACCESS_KEY.")
            elif error_code == 'AccessDenied':
                logger.error(f"❌ Access denied. Your AWS user may not have sufficient permissions.")
            else:
                logger.error(f"❌ AWS API error ({error_code}): {error_message}")
            
            return False

        except Exception as e:
            logger.error(f"❌ Credential validation failed: {e}")
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
            f"export ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0 && "
            f"export ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0"
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
        from datetime import datetime, timezone

        # Get current time in UTC with timezone info
        now = datetime.now(timezone.utc)
        expiration = credentials['expiration']
        
        # Ensure expiration has timezone info
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)

        output = {
            "aws_credentials": {
                "access_key_id": credentials['access_key'],
                "secret_access_key": credentials['secret_key'],
                "session_token": credentials['token'],
                "expiration": expiration.isoformat()
            },
            "claude_config": {
                "use_bedrock": True,
                "region": region,
                "primary_model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
                "fast_model": "us.anthropic.claude-sonnet-4-20250514-v1:0"
            },
            "metadata": {
                "generated_at": now.isoformat(),
                "duration_hours": round((expiration - now).total_seconds() / 3600, 1)
            }
        }

        return json.dumps(output, indent=2)
