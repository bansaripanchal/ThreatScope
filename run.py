#!/usr/bin/env python
"""
ThreatScope V2 - Standalone Launcher
"""

from app import create_app
from config import Config

if __name__ == "__main__":
    app = create_app()
    print("==================================================================")
    print("  THREATSCOPE V2 - ATTACK SURFACE INTELLIGENCE & RECONNAISSANCE   ")
    print("==================================================================")
    print(" Server running at: http://127.0.0.1:5000")
    print(" Press CTRL+C to stop.")
    print("==================================================================")
    # use_reloader=False prevents WinError 10038 on Windows when database writes occur
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG, use_reloader=False)
