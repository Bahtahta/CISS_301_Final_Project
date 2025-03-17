@echo off
echo Installing required Python packages...
python -m pip install --upgrade pip
pip install sqlite3
pip install pefile
pip install hashlib
pip install pathlib
pip install subprocess
pip install tempfile
pip install base64
pip install collections
pip install re
pip install os

echo Installation complete!
pause
