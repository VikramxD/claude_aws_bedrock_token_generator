# AWS Bedrock Credential Helper

A production-ready utility for generating temporary AWS credentials for Amazon Bedrock, specifically designed for seamless integration with Claude Code.

## 🚀 Features

- **Secure Credential Management**: No hardcoded credentials - uses environment variables
- **Multiple Output Formats**: Export commands, JSON, or formatted tables
- **Production Ready**: Comprehensive logging, error handling, and testing
- **Claude Code Integration**: Pre-configured for Claude Code with Bedrock
- **Modern CLI**: Built with Typer for excellent user experience
- **Flexible Configuration**: Customizable regions, token duration, and output formats

## 📋 Prerequisites

- Python 3.11 or higher
- AWS account with Bedrock access
- Valid AWS credentials (Access Key ID and Secret Access Key)

## 🛠️ Installation

### Using uv (Recommended)

```bash
git clone https://github.com/VikramxD/claude_aws_bedrock_token_generator.git
cd claude_aws-bedrock-credential-helper
uv sync
```

### Using pip

```bash
git clone https://github.com/VikramxD/claude_aws_bedrock_token_generator.git
cd claude_aws-bedrock-credential-helper
pip install -r requirements.txt
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root (use `.env.example` as a template):

```bash
# AWS Credentials
AWS_ACCESS_KEY_ID="your_aws_access_key_id"
AWS_SECRET_ACCESS_KEY="your_aws_secret_access_key"

# Optional Configuration
AWS_REGION="us-east-1"
DURATION_SECONDS=129600  # 36 hours
```

### AWS Setup

1. **Enable Bedrock Access**: Ensure your AWS account has access to Amazon Bedrock
2. **Request Model Access**: In the Bedrock console, request access to Claude models
3. **IAM Permissions**: Ensure your AWS user has the necessary permissions:
   - `sts:GetSessionToken`
   - `bedrock:InvokeModel`
   - `bedrock:ListFoundationModels`

## 🎯 Usage

### Basic Usage

Generate credentials in export format (default):

```bash
python src/main.py generate
```

### Advanced Usage

```bash
# Custom region and duration
python src/main.py generate --region us-west-2 --duration 7200

# JSON output format
python src/main.py generate --format json

# Table format for human reading
python src/main.py generate --format table

# Quiet mode (suppress logs)
python src/main.py generate --quiet
```

### Validate Credentials

```bash
python src/main.py validate
```

### CLI Help

```bash
python src/main.py --help
python src/main.py generate --help
```

## 📤 Output Formats

### Export Format (Default)

Perfect for copying and pasting into your terminal:

```bash
export AWS_ACCESS_KEY_ID=ASIATEMP123... && export AWS_SECRET_ACCESS_KEY=temp_secret... && export AWS_SESSION_TOKEN=temp_session... && export CLAUDE_CODE_USE_BEDROCK=1 && export AWS_REGION=us-east-1 && export ANTHROPIC_MODEL=us.anthropic.claude-opus-4-20250514-v1:0 && export ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-4-sonnet-20250109-v1:0
```

### JSON Format

Structured data for programmatic use:

```json
{
  "aws_credentials": {
    "access_key_id": "ASIATEMP123...",
    "secret_access_key": "temp_secret...",
    "session_token": "temp_session...",
    "expiration": "2024-01-01T12:00:00+00:00"
  },
  "claude_config": {
    "use_bedrock": true,
    "region": "us-east-1",
    "primary_model": "us.anthropic.claude-opus-4-20250514-v1:0",
    "fast_model": "us.anthropic.claude-4-sonnet-20250109-v1:0"
  }
}
```

### Table Format

Human-readable table display with credential details.

## 🔧 Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Run specific test file
uv run pytest tests/test_core.py
```

### Code Quality

```bash
# Install development dependencies
uv sync --dev

# Run linting
uv run ruff check src/ tests/

# Fix linting issues
uv run ruff check --fix src/ tests/

# Type checking
uv run mypy src/
```

### Documentation

Generate documentation:

```bash
cd docs
uv run sphinx-build -b html source build
```

## 🏗️ Architecture

The project follows a clean architecture with clear separation of concerns:

```
src/
├── main.py          # CLI interface and application entry point
└── core.py          # Core business logic and AWS integration

tests/
├── test_cli.py      # CLI interface tests
└── test_core.py     # Core functionality tests

docs/
└── source/          # Sphinx documentation source
```

### Key Components

- **AWSCredentialManager**: Handles AWS STS token generation and validation
- **ClaudeCodeFormatter**: Formats credentials for different output formats
- **CLI Interface**: Typer-based command-line interface with rich output

## 🔒 Security Considerations

- **No Hardcoded Credentials**: All credentials are loaded from environment variables
- **Temporary Tokens**: Generated tokens have configurable expiration times
- **Secure Logging**: Sensitive information is never logged
- **Environment Isolation**: Uses `.env` files for local development

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `uv run pytest`
6. Run code quality checks: `uv run ruff check src/ tests/`
7. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Troubleshooting

### Common Issues

**"AWS credentials not found"**
- Ensure `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set in your environment or `.env` file

**"No valid AWS credentials found"**
- Check that your AWS credentials are valid and have the necessary permissions
- Run `python src/main.py validate` to test your credentials

**"Token generation failed"**
- Verify your AWS account has access to STS
- Check that your credentials have `sts:GetSessionToken` permission
- Ensure the specified region is valid

**"Module not found errors"**
- Make sure you've installed dependencies: `uv sync` or `pip install -r requirements.txt`
- Ensure you're running from the project root directory

### Getting Help

- Check the CLI help: `python src/main.py --help`
- Review the troubleshooting section above
- Open an issue on GitHub with detailed error information

## 📚 Additional Resources

- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code/overview)
- [Anthropic Claude Code on Amazon Bedrock Setup Guide](https://docs.anthropic.com/en/docs/claude-code/amazon-bedrock)

## 🔄 Quick Start Example

1. **Clone and setup**:
   ```bash
   git clone https://github.com/VikramxD/claude_aws_bedrock_token_generator.git
   cd claude_aws-bedrock-credential-helper
   uv sync
   ```

2. **Configure credentials**:
   ```bash
   cp .env.example .env
   # Edit .env with your AWS credentials
   ```

3. **Generate credentials**:
   ```bash
   python src/main.py generate
   ```

4. **Copy and paste the output** into your terminal to set up Claude Code with Bedrock!
