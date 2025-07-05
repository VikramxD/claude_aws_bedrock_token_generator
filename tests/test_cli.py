"""
Tests for the CLI interface.
"""

import json
import os
import sys
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import CredentialError, app, get_aws_credentials


class TestCLI:
    """Test cases for CLI interface."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.mock_credentials = {
            'access_key': 'ASIATEMP123456789',
            'secret_key': 'temp_secret_key',
            'token': 'temp_session_token',
            'expiration': datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        }

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    def test_get_aws_credentials_success(self):
        """Test successful retrieval of AWS credentials from environment."""
        access_key, secret_key = get_aws_credentials()
        assert access_key == 'AKIATEST123'
        assert secret_key == 'test_secret'

    @patch.dict(os.environ, {}, clear=True)
    def test_get_aws_credentials_missing(self):
        """Test handling of missing AWS credentials."""
        with pytest.raises(CredentialError):
            get_aws_credentials()

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_generate_command_export_format(self, mock_manager_class):
        """Test generate command with export format."""
        # Mock the credential manager
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.generate_session_token.return_value = self.mock_credentials

        # Run the command
        result = self.runner.invoke(app, ['generate', '--format', 'export'])

        # Assertions
        assert result.exit_code == 0
        assert 'export AWS_ACCESS_KEY_ID=ASIATEMP123456789' in result.stdout
        assert 'export CLAUDE_CODE_USE_BEDROCK=1' in result.stdout

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_generate_command_json_format(self, mock_manager_class):
        """Test generate command with JSON format."""
        # Mock the credential manager
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.generate_session_token.return_value = self.mock_credentials

        # Run the command
        result = self.runner.invoke(app, ['generate', '--format', 'json'])

        # Assertions
        assert result.exit_code == 0

        # Parse the JSON output
        output_data = json.loads(result.stdout)
        assert 'aws_credentials' in output_data
        assert 'claude_config' in output_data
        assert output_data['aws_credentials']['access_key_id'] == 'ASIATEMP123456789'

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_generate_command_failure(self, mock_manager_class):
        """Test generate command when credential generation fails."""
        # Mock the credential manager to return None (failure)
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.generate_session_token.return_value = None

        # Run the command
        result = self.runner.invoke(app, ['generate'])

        # Assertions
        assert result.exit_code == 1

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_validate_command_success(self, mock_manager_class):
        """Test validate command with successful validation."""
        # Mock the credential manager
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.validate_credentials.return_value = True

        # Run the command
        result = self.runner.invoke(app, ['validate'])

        # Assertions
        assert result.exit_code == 0

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_validate_command_failure(self, mock_manager_class):
        """Test validate command with failed validation."""
        # Mock the credential manager
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.validate_credentials.return_value = False

        # Run the command
        result = self.runner.invoke(app, ['validate'])

        # Assertions
        assert result.exit_code == 1

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_credentials_error(self):
        """Test handling of missing credentials in CLI."""
        result = self.runner.invoke(app, ['generate'])

        # Should exit with error code
        assert result.exit_code == 1

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIATEST123', 'AWS_SECRET_ACCESS_KEY': 'test_secret'})
    @patch('main.AWSCredentialManager')
    def test_custom_region_and_duration(self, mock_manager_class):
        """Test custom region and duration parameters."""
        # Mock the credential manager
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager
        mock_manager.generate_session_token.return_value = self.mock_credentials

        # Run the command with custom parameters
        result = self.runner.invoke(app, [
            'generate',
            '--region', 'us-west-2',
            '--duration', '7200',
            '--format', 'export'
        ])

        # Assertions
        assert result.exit_code == 0

        # Verify the manager was initialized with correct region
        mock_manager_class.assert_called_with('AKIATEST123', 'test_secret', 'us-west-2')

        # Verify generate_session_token was called with correct duration
        mock_manager.generate_session_token.assert_called_with(7200)
