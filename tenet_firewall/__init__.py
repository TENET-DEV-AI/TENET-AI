"""TENET AI — client SDK for the TENET defensive middleware.

    from tenet_firewall import TenetSecurityPlugin

    guard = TenetSecurityPlugin(api_url="http://localhost:8000", api_key="...")
    result = guard.secure_call(prompt=user_input, model="gpt-4", llm_callable=model)

The package is the client only. The ingest and analyzer services run from the
repository (docker compose up -d).
"""

from importlib.metadata import PackageNotFoundError, version

from .client import TenetSecurityPlugin, TenetPluginError

try:
    __version__ = version("tenet-firewall")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.0.0.dev0"

__all__ = ["TenetSecurityPlugin", "TenetPluginError", "__version__"]
