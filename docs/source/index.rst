AWS Bedrock Credential Helper Documentation
===========================================

Welcome to the AWS Bedrock Credential Helper documentation. This utility provides a secure, production-ready way to generate temporary AWS credentials for Amazon Bedrock, specifically designed for seamless integration with Claude Code.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   api
   cli
   troubleshooting

Features
--------

* **Secure Credential Management**: No hardcoded credentials - uses environment variables
* **Multiple Output Formats**: Export commands, JSON, or formatted tables  
* **Production Ready**: Comprehensive logging, error handling, and testing
* **Claude Code Integration**: Pre-configured for Claude Code with Bedrock
* **Modern CLI**: Built with Typer for excellent user experience
* **Flexible Configuration**: Customizable regions, token duration, and output formats

Quick Start
-----------

1. Install dependencies::

    uv sync

2. Configure environment variables::

    export AWS_ACCESS_KEY_ID="your_access_key"
    export AWS_SECRET_ACCESS_KEY="your_secret_key"

3. Generate credentials::

    python src/main.py generate

API Reference
=============

.. automodule:: core
   :members:

.. automodule:: main
   :members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
