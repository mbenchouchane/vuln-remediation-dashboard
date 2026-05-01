"""Main entry point for the MS17-010 Remediation Agent."""

import sys
from typing import Optional

import click
from loguru import logger

from config.settings import settings
from src.agent import RemediationAgent


def setup_logging():
    """Configure logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=settings.LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    )
    logger.add(
        "remediation.log",
        rotation="10 MB",
        retention="7 days",
        level="DEBUG",
    )


@click.command()
@click.option(
    "--target", "-t",
    help="Specific target host to remediate (IP or hostname)",
)
@click.option(
    "--dry-run", "-n",
    is_flag=True,
    help="Check status without making changes",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
def main(target: Optional[str], dry_run: bool, verbose: bool):
    """MS17-010 Remediation Agent.

    Automates the remediation of EternalBlue vulnerability by disabling SMBv1
    on Windows machines.
    """
    setup_logging()

    if verbose:
        settings.LOG_LEVEL = "DEBUG"

    if dry_run:
        settings.DRY_RUN = True
        logger.info("Running in dry-run mode - no changes will be made")

    agent = RemediationAgent()
    results = agent.run(target=target)

    # Print summary
    click.echo("\n" + "=" * 50)
    click.echo("REMEDIATION SUMMARY")
    click.echo("=" * 50)
    click.echo(f"Total hosts processed: {results['total']}")
    click.echo(f"Successful: {results['success']}")
    click.echo(f"Failed: {results['failed']}")

    if results["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
