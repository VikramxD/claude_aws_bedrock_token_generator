"""
Production-ready AWS Bedrock Credential Helper CLI

This utility generates temporary AWS credentials for Amazon Bedrock
and outputs them in various formats for easy integration with Claude Code.
"""

import os
import sys

import typer
from dotenv import load_dotenv
from loguru import logger
from rich.console import Console
from rich.table import Table

from core import AWSCredentialManager, ClaudeCodeFormatter

# Load environment variables from .env file
load_dotenv()

# Initialize Rich console for beautiful output
console = Console()

# Configure Loguru to output to stderr only
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)

# Configuration with environment variable fallbacks
DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
DEFAULT_DURATION = int(os.getenv("DURATION_SECONDS", "129600"))  # 36 hours

app = typer.Typer(
    name="bedrock-credentials",
    help="Generate temporary AWS credentials for Amazon Bedrock",
    add_completion=False
)


class CredentialError(Exception):
    """Custom exception for credential-related errors."""
    pass


def get_aws_credentials() -> tuple[str, str]:
    """
    Retrieve AWS credentials from environment variables.

    Returns:
        tuple: (access_key, secret_key)

    Raises:
        CredentialError: If credentials are not found or invalid
    """
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

    if not access_key or not secret_key:
        raise CredentialError(
            "AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
        )

    return access_key, secret_key


@app.command()
def generate(
    region: str = typer.Option(DEFAULT_REGION, "--region", "-r", help="AWS region"),
    duration: int = typer.Option(DEFAULT_DURATION, "--duration", "-d", help="Token duration in seconds"),
    output_format: str = typer.Option("export", "--format", "-f", help="Output format: export, json, table"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress log output")
):
    """
    Generate temporary AWS credentials for Bedrock.

    The credentials are output to stdout in the specified format,
    while all logging goes to stderr.
    """
    if quiet:
        logger.remove()
        logger.add(sys.stderr, level="ERROR")

    try:
        # Get base AWS credentials
        access_key, secret_key = get_aws_credentials()

        # Initialize credential manager
        credential_manager = AWSCredentialManager(access_key, secret_key, region)

        # Generate session token
        credentials = credential_manager.generate_session_token(duration)

        if not credentials:
            logger.error("Failed to generate session token")
            raise typer.Exit(1) from None

        # Output to stdout based on format
        if output_format == "export":
            print(ClaudeCodeFormatter.format_export_command(credentials, region))
        elif output_format == "json":
            print(ClaudeCodeFormatter.format_json_output(credentials, region))
        elif output_format == "table":
            table = Table(title="AWS Bedrock Credentials")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Access Key ID", credentials['access_key'])
            table.add_row("Secret Access Key", credentials['secret_key'][:20] + "...")
            table.add_row("Session Token", credentials['token'][:30] + "...")
            table.add_row("Expiration", str(credentials['expiration']))
            table.add_row("Region", region)

            console.print(table)
        else:
            logger.error(f"Unknown output format: {output_format}")
            raise typer.Exit(1) from None

    except CredentialError as e:
        logger.error(str(e))
        raise typer.Exit(1) from None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command()
def validate():
    """
    Validate that AWS credentials are properly configured.
    """
    try:
        access_key, secret_key = get_aws_credentials()
        logger.info("AWS credentials found in environment")

        # Initialize credential manager and validate
        credential_manager = AWSCredentialManager(access_key, secret_key)

        if not credential_manager.validate_credentials():
            raise typer.Exit(1) from None

    except CredentialError as e:
        logger.error(str(e))
        raise typer.Exit(1) from None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


if __name__ == "__main__":
    app()
