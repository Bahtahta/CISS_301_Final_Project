#!/bin/bash
echo "Installing required Python packages..."

python3 -m pip install --upgrade pip

pip3 install sqlite3 pefile pathlib subprocess tempfile base64 collections re os

echo "Installation complete!"
