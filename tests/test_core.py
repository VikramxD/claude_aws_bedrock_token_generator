"""
Tests for the core AWS credential management functionality.
"""

import os
import sys
from datetime import UTC, datetime
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError, NoCredentialsError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core import AWSCredentialManager, ClaudeCodeFormatter


class TestAWSCredentialManager:
    """Test cases for AWSCredentialManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.access_key = "AKIATEST123456789"
        self.secret_key = "test_secret_key_123456789"
        self.region = "us-east-1"
        self.manager = AWSCredentialManager(self.access_key, self.secret_key, self.region)

    @patch('core.boto3.client')
    def test_generate_session_token_success(self, mock_boto_client):
        """Test successful session token generation."""
        # Mock the STS client and response
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        mock_expiration = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        mock_response = {
            'Credentials': {
                'AccessKeyId': 'ASIATEMP123456789',
                'SecretAccessKey': 'temp_secret_key',
                'SessionToken': 'temp_session_token',
                'Expiration': mock_expiration
            }
        }
        mock_sts.get_session_token.return_value = mock_response

        # Test the method
        result = self.manager.generate_session_token(duration_seconds=3600)

        # Assertions
        assert result is not None
        assert result['access_key'] == 'ASIATEMP123456789'
        assert result['secret_key'] == 'temp_secret_key'
        assert result['token'] == 'temp_session_token'
        assert result['expiration'] == mock_expiration

        # Verify boto3 client was called correctly
        mock_boto_client.assert_called_once_with(
            'sts',
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region
        )
        mock_sts.get_session_token.assert_called_once_with(DurationSeconds=3600)

    @patch('core.boto3.client')
    def test_generate_session_token_client_error(self, mock_boto_client):
        """Test handling of AWS client errors."""
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        # Mock a ClientError
        error_response = {
            'Error': {
                'Code': 'InvalidUserID.NotFound',
                'Message': 'The user ID does not exist'
            }
        }
        mock_sts.get_session_token.side_effect = ClientError(error_response, 'GetSessionToken')

        # Test the method
        result = self.manager.generate_session_token()

        # Assertions
        assert result is None

    @patch('core.boto3.client')
    def test_generate_session_token_no_credentials_error(self, mock_boto_client):
        """Test handling of no credentials error."""
        mock_boto_client.side_effect = NoCredentialsError()

        # Test the method
        result = self.manager.generate_session_token()

        # Assertions
        assert result is None

    @patch('core.boto3.client')
    def test_validate_credentials_success(self, mock_boto_client):
        """Test successful credential validation."""
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        mock_identity = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/testuser'
        }
        mock_sts.get_caller_identity.return_value = mock_identity

        # Test the method
        result = self.manager.validate_credentials()

        # Assertions
        assert result is True
        mock_sts.get_caller_identity.assert_called_once()

    @patch('core.boto3.client')
    def test_validate_credentials_failure(self, mock_boto_client):
        """Test credential validation failure."""
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        mock_sts.get_caller_identity.side_effect = Exception("Invalid credentials")

        # Test the method
        result = self.manager.validate_credentials()

        # Assertions
        assert result is False


class TestClaudeCodeFormatter:
    """Test cases for ClaudeCodeFormatter class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.credentials = {
            'access_key': 'ASIATEMP123456789',
            'secret_key': 'temp_secret_key',
            'token': 'temp_session_token',
            'expiration': datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        }
        self.region = 'us-east-1'

    def test_format_export_command(self):
        """Test export command formatting."""
        result = ClaudeCodeFormatter.format_export_command(self.credentials, self.region)

        # Check that all required exports are present
        assert 'export AWS_ACCESS_KEY_ID=ASIATEMP123456789' in result
        assert 'export AWS_SECRET_ACCESS_KEY=temp_secret_key' in result
        assert 'export AWS_SESSION_TOKEN=temp_session_token' in result
        assert 'export CLAUDE_CODE_USE_BEDROCK=1' in result
        assert 'export AWS_REGION=us-east-1' in result
        assert 'export ANTHROPIC_MODEL=us.anthropic.claude-opus-4-20250514-v1:0' in result
        assert 'export ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-4-sonnet-20250109-v1:0' in result

        # Check that commands are joined with &&
        assert '&&' in result

    def test_format_json_output(self):
        """Test JSON output formatting."""
        import json

        result = ClaudeCodeFormatter.format_json_output(self.credentials, self.region)

        # Parse the JSON to verify structure
        parsed = json.loads(result)

        # Check aws_credentials section
        assert 'aws_credentials' in parsed
        aws_creds = parsed['aws_credentials']
        assert aws_creds['access_key_id'] == 'ASIATEMP123456789'
        assert aws_creds['secret_access_key'] == 'temp_secret_key'
        assert aws_creds['session_token'] == 'temp_session_token'
        assert aws_creds['expiration'] == '2024-01-01T12:00:00+00:00'

        # Check claude_config section
        assert 'claude_config' in parsed
        claude_config = parsed['claude_config']
        assert claude_config['use_bedrock'] is True
        assert claude_config['region'] == 'us-east-1'
        assert claude_config['primary_model'] == 'us.anthropic.claude-opus-4-20250514-v1:0'
        assert claude_config['fast_model'] == 'us.anthropic.claude-4-sonnet-20250109-v1:0'
