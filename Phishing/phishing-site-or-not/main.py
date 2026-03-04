"""Convenience entry point for the phishing detection CLI.

This script is intentionally minimal: it loads the package
and delegates to ``run_cli``.  All user interaction has been
removed and every invocation produces *only* JSON on stdout.
Logging (if any) goes to stderr.

Usage:
    python main.py example.com

If the import or execution fails the error will be emitted
as a JSON object and the process will terminate.
"""

import sys
import json

try:
    # only import the function we need; initialization
    # in phishing.main already loads the model
    from phishing.main import run_cli
except Exception as e:
    sys.stdout.write(json.dumps({"error": str(e)}))
    sys.exit(1)

if __name__ == "__main__":
    run_cli()
