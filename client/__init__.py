"""Clients for cowork-tunnel: SSH over WebSocket, and HTTP forwarding.

Both modules are also usable as standalone files -- bootstrap.sh downloads them
individually, which is the fallback for environments where pip is unavailable.
Nothing here may import anything outside the standard library except websockets.
"""

__version__ = "2.1.2"
