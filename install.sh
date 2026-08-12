#!/bin/bash
echo "[*] Installing ShieldProbe dependencies..."
pip install -r requirements.txt --break-system-packages
echo "[✓] Done. Run: python shieldprobe.py --help"
