"""
Production-ready AWS Bedrock Credential Helper CLI

This utility generates temporary AWS credentials for Amazon Bedrock
and outputs them in various formats for easy integration with Claude Code.
"""

import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from core import AWSCredentialManager, ClaudeCodeFormatter

# Load environment variables from .env file with explicit path
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path, override=True)

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
DEFAULT_REGION = os.getenv("AWS_REGION") or os.getenv("REGION", "us-east-1")
DEFAULT_DURATION = int(os.getenv("DURATION_SECONDS", "129600"))  # 36 hours

app = typer.Typer(
    name="bedrock-credentials",
    help="🚀 Generate temporary AWS credentials for Amazon Bedrock",
    add_completion=False,
    rich_markup_mode="rich"
)


class CredentialError(Exception):
    """Custom exception for credential-related errors."""
    pass


def print_banner():
    """Print a beautiful banner for the application."""
    banner = Text.assemble(
        ("🔐 ", "bold blue"),
        ("AWS Bedrock Credential Helper", "bold white"),
        (" 🚀", "bold blue")
    )
    console.print(Panel(
        banner,
        box=box.ROUNDED,
        padding=(1, 2),
        style="blue"
    ))


def print_config_info():
    """Print current configuration information."""
    config_table = Table(title="📋 Current Configuration", box=box.ROUNDED)
    config_table.add_column("Setting", style="cyan", no_wrap=True)
    config_table.add_column("Value", style="green")
    config_table.add_column("Source", style="yellow")
    
    # Check AWS credentials
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    
    config_table.add_row(
        "AWS Access Key", 
        f"{aws_key[:10]}..." if aws_key else "❌ Not Set",
        "Environment" if aws_key else "Missing"
    )
    config_table.add_row(
        "AWS Secret Key", 
        "✅ Set" if aws_secret else "❌ Not Set",
        "Environment" if aws_secret else "Missing"
    )
    config_table.add_row(
        "Default Region", 
        DEFAULT_REGION,
        "REGION/AWS_REGION env var" if os.getenv("AWS_REGION") or os.getenv("REGION") else "Default"
    )
    config_table.add_row(
        "Default Duration", 
        f"{DEFAULT_DURATION} seconds ({DEFAULT_DURATION/3600:.1f} hours)",
        "DURATION_SECONDS env var" if os.getenv("DURATION_SECONDS") else "Default"
    )
    
    console.print(config_table)
    console.print()


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
        console.print("❌ [bold red]AWS credentials not found![/bold red]")
        console.print("Please set the following environment variables:")
        console.print("• [cyan]AWS_ACCESS_KEY_ID[/cyan]")
        console.print("• [cyan]AWS_SECRET_ACCESS_KEY[/cyan]")
        console.print("\nOr create a [cyan].env[/cyan] file with these values.")
        raise CredentialError(
            "AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
        )

    return access_key, secret_key


@app.command()
def generate(
    region: str = typer.Option(
        DEFAULT_REGION, 
        "--region", "-r", 
        help="🌍 AWS region to use",
        rich_help_panel="🔧 Configuration Options"
    ),
    duration: int = typer.Option(
        DEFAULT_DURATION, 
        "--duration", "-d", 
        help="⏰ Token duration in seconds (default: 36 hours)",
        rich_help_panel="🔧 Configuration Options"
    ),
    output_format: str = typer.Option(
        "export", 
        "--format", "-f", 
        help="�� Output format: [bold]export[/bold], [bold]json[/bold], [bold]table[/bold]",
        rich_help_panel="📋 Output Options"
    ),
    quiet: bool = typer.Option(
        False, 
        "--quiet", "-q", 
        help="🔇 Suppress log output",
        rich_help_panel="🎛️ Display Options"
    ),
    show_config: bool = typer.Option(
        False, 
        "--show-config", 
        help="📋 Show current configuration",
        rich_help_panel="🎛️ Display Options"
    ),
    no_banner: bool = typer.Option(
        False, 
        "--no-banner", 
        help="🚫 Hide the banner",
        rich_help_panel="🎛️ Display Options"
    )
):
    """
    🎯 Generate temporary AWS credentials for Bedrock.

    The credentials are output to stdout in the specified format,
    while all logging goes to stderr for easy piping.

    [bold green]Examples:[/bold green]
    • [cyan]python src/main.py generate[/cyan] - Basic usage
    • [cyan]python src/main.py generate --format json[/cyan] - JSON output
    • [cyan]python src/main.py generate --duration 43200[/cyan] - 12 hour token
    • [cyan]eval "$(python src/main.py generate --quiet)"[/cyan] - Set env vars directly
    """
    if not no_banner and not quiet:
        print_banner()
    
    if show_config and not quiet:
        print_config_info()
    
    if quiet:
        logger.remove()
        logger.add(sys.stderr, level="ERROR")

    try:
        # Get base AWS credentials
        access_key, secret_key = get_aws_credentials()

        # Show operation details
        if not quiet:
            operation_table = Table(title="🔄 Operation Details", box=box.SIMPLE)
            operation_table.add_column("Parameter", style="cyan")
            operation_table.add_column("Value", style="green")
            
            operation_table.add_row("Region", region)
            operation_table.add_row("Duration", f"{duration} seconds ({duration/3600:.1f} hours)")
            operation_table.add_row("Output Format", output_format.upper())
            
            console.print(operation_table)
            console.print()

        # Initialize credential manager
        credential_manager = AWSCredentialManager(access_key, secret_key, region)

        # Generate session token with progress indicator
        if not quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("🔐 Generating session token...", total=None)
                credentials = credential_manager.generate_session_token(duration)
        else:
            credentials = credential_manager.generate_session_token(duration)

        if not credentials:
            if not quiet:
                console.print("❌ [bold red]Failed to generate session token[/bold red]")
            logger.error("Failed to generate session token")
            raise typer.Exit(1) from None

        # Success message
        if not quiet:
            console.print("✅ [bold green]Session token generated successfully![/bold green]")
            console.print(f"🕒 [yellow]Expires at: {credentials['expiration']}[/yellow]")
            console.print()

        # Output to stdout based on format
        if output_format == "export":
            if not quiet:
                console.print("📋 [bold cyan]Copy and paste the following command:[/bold cyan]")
                console.print()
            print(ClaudeCodeFormatter.format_export_command(credentials, region))
            
        elif output_format == "json":
            if not quiet:
                console.print("📋 [bold cyan]JSON Output:[/bold cyan]")
                console.print()
            print(ClaudeCodeFormatter.format_json_output(credentials, region))
            
        elif output_format == "table":
            table = Table(
                title="🔐 AWS Bedrock Credentials", 
                box=box.ROUNDED,
                title_style="bold blue"
            )
            table.add_column("🔑 Key", style="cyan", no_wrap=True)
            table.add_column("📋 Value", style="green")

            table.add_row("Access Key ID", credentials['access_key'])
            table.add_row("Secret Access Key", credentials['secret_key'][:20] + "...")
            table.add_row("Session Token", credentials['token'][:50] + "...")
            table.add_row("Expiration", str(credentials['expiration']))
            table.add_row("Region", region)
            table.add_row("Duration", f"{duration} seconds ({duration/3600:.1f} hours)")

            console.print(table)
            
            # Show Claude Code exports
            console.print("\n📋 [bold cyan]Claude Code Environment Variables:[/bold cyan]")
            claude_table = Table(box=box.SIMPLE)
            claude_table.add_column("Variable", style="cyan")
            claude_table.add_column("Value", style="green")
            
            claude_table.add_row("CLAUDE_CODE_USE_BEDROCK", "1")
            claude_table.add_row("AWS_REGION", region)
            claude_table.add_row("ANTHROPIC_MODEL", "us.anthropic.claude-opus-4-20250514-v1:0")
            claude_table.add_row("ANTHROPIC_SMALL_FAST_MODEL", "us.anthropic.claude-4-sonnet-20250109-v1:0")
            
            console.print(claude_table)
            
        else:
            console.print(f"❌ [bold red]Unknown output format: {output_format}[/bold red]")
            logger.error(f"Unknown output format: {output_format}")
            raise typer.Exit(1) from None

        if not quiet and output_format != "table":
            console.print("\n💡 [bold yellow]Tip:[/bold yellow] Use [cyan]--format table[/cyan] for a detailed view")
            console.print("💡 [bold yellow]Tip:[/bold yellow] Use [cyan]--quiet[/cyan] for script-friendly output")

    except CredentialError as e:
        logger.error(str(e))
        raise typer.Exit(1) from None
    except Exception as e:
        console.print(f"❌ [bold red]Unexpected error: {e}[/bold red]")
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command()
def validate():
    """
    ✅ Validate that AWS credentials are properly configured.
    
    This command checks if your AWS credentials are valid and can access AWS services.
    """
    print_banner()
    
    try:
        console.print("🔍 [bold cyan]Validating AWS credentials...[/bold cyan]")
        console.print()
        
        access_key, secret_key = get_aws_credentials()
        
        # Show credential info
        cred_table = Table(title="🔑 Credential Information", box=box.ROUNDED)
        cred_table.add_column("Item", style="cyan")
        cred_table.add_column("Status", style="green")
        
        cred_table.add_row("Access Key ID", f"{access_key[:10]}...{access_key[-4:]}")
        cred_table.add_row("Secret Key", "✅ Present")
        
        console.print(cred_table)
        console.print()

        # Initialize credential manager and validate
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("🔐 Validating credentials with AWS...", total=None)
            credential_manager = AWSCredentialManager(access_key, secret_key)
            is_valid = credential_manager.validate_credentials()

        if is_valid:
            console.print("✅ [bold green]AWS credentials are valid![/bold green]")
            console.print("🎉 [bold yellow]You're ready to generate session tokens![/bold yellow]")
        else:
            console.print("❌ [bold red]AWS credential validation failed![/bold red]")
            raise typer.Exit(1) from None

    except CredentialError as e:
        logger.error(str(e))
        raise typer.Exit(1) from None
    except Exception as e:
        console.print(f"❌ [bold red]Unexpected error: {e}[/bold red]")
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command()
def config():
    """
    📋 Show current configuration and environment setup.
    
    This command displays all configuration values and their sources.
    """
    print_banner()
    print_config_info()
    
    # Check .env file
    env_file_exists = env_path.exists()
    console.print(f"📄 [bold cyan].env file:[/bold cyan] {'✅ Found' if env_file_exists else '❌ Not found'}")
    
    if env_file_exists:
        console.print(f"📍 [yellow]Location: {env_path.absolute()}[/yellow]")
    else:
        console.print("💡 [yellow]Create a .env file using .env.example as a template[/yellow]")
    
    console.print()
    
    # Show example .env content
    console.print("📝 [bold cyan]Example .env file content:[/bold cyan]")
    example_panel = Panel(
        """AWS_ACCESS_KEY_ID="your_access_key_here"
AWS_SECRET_ACCESS_KEY="your_secret_key_here"
REGION="us-east-1"
DURATION_SECONDS=129600""",
        box=box.ROUNDED,
        title="📄 .env",
        title_align="left"
    )
    console.print(example_panel)


if __name__ == "__main__":
    app()
