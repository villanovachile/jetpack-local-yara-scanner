#!/bin/bash

BIN_DIR="$HOME/bin"
VENV_DIR="$BIN_DIR/scan_env"
SCAN_SCRIPT_URL="https://raw.githubusercontent.com/villanovachile/jetpack-local-yara-scanner/main/scan/scan"
SCAN_PY_URL="https://raw.githubusercontent.com/villanovachile/jetpack-local-yara-scanner/main/scan/scan.py"

check_yarac_installed() {
    if ! command -v yarac &>/dev/null; then
        echo "Error: 'yarac' (YARA compiler) is not installed or not in your PATH."
        echo "Please install YARA before proceeding. For example:"
        echo "  macOS: brew install yara"
        echo "  Debian/Ubuntu: sudo apt install yara"
        echo "  Fedora: sudo dnf install yara"
        echo "After installation, rerun this script."
        exit 1
    fi
}

check_yarac_installed

mkdir -p "$BIN_DIR"

echo "Downloading files from GitHub..."
curl -o "$BIN_DIR/scan" "$SCAN_SCRIPT_URL"
curl -o "$BIN_DIR/scan.py" "$SCAN_PY_URL"

echo "Configuring $BIN_DIR/scan.py..."
if [ -f "$BIN_DIR/scan.py" ]; then

    YARA_REPO=$(find "$HOME" -maxdepth 2 -type d -name "waffle-makers-yara-rules" 2>/dev/null | head -n 1)
    if [ -n "$YARA_REPO" ]; then
        echo "Found yara repo at: $YARA_REPO"

        if [ -d "$YARA_REPO/signatures/YARA" ]; then
            echo "Found 'signatures/YARA' within $YARA_REPO. Do you want to use this path? (y/n)"
            read -r USE_YARA_REPO
            if [ "$USE_YARA_REPO" != "y" ]; then
                YARA_REPO=""
            fi
        else
            echo "Error: 'signatures/YARA' not found in '$YARA_REPO'."
            YARA_REPO=""
        fi
    fi

    while [ -z "$YARA_REPO" ]; do
        echo "Please enter the full path to your yara repo folder (e.g., ~/repos/waffle-makers-yara-rules):"
        read -r YARA_REPO

        YARA_REPO=$(eval echo "$YARA_REPO")
        echo "Checking: $YARA_REPO/signatures/YARA"

        if [ ! -d "$YARA_REPO/signatures/YARA" ]; then
            echo "Error: 'signatures/YARA' not found in '$YARA_REPO'. Please try again."
            YARA_REPO=""
        fi
    done

    sed -i.bak "s|BASE_DIR = os.path.expanduser('path/to/yara/repo')|BASE_DIR = os.path.expanduser('$YARA_REPO')|" "$BIN_DIR/scan.py"

    echo "$BIN_DIR/scan.py configured successfully."
else
    echo "Error: $BIN_DIR/scan.py not found."
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists at $VENV_DIR."
fi

echo "Activating virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install yara-python tqdm
deactivate

echo "Making scan script executable..."
chmod +x "$BIN_DIR/scan"

echo "Installation complete! You can now run 'scan' in Terminal from your current working directory."
