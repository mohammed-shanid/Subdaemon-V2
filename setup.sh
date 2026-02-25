#!/bin/bash

# 1. Cleanup: Remove old/messy directories
echo "🧹 Cleaning up old project structure..."
rm -rf subdaemon/ config/ core/ sources/ output/ cli/ 

# 2. Create the new nested structure
echo "📂 Creating professional package structure..."
mkdir -p subdaemon/config
mkdir -p subdaemon/core
mkdir -p subdaemon/sources
mkdir -p subdaemon/output
mkdir -p subdaemon/cli

# 3. Create __init__.py files for package recognition
echo "🐍 Creating Python package files..."
touch subdaemon/__init__.py
touch subdaemon/config/__init__.py
touch subdaemon/core/__init__.py
touch subdaemon/sources/__init__.py
touch subdaemon/output/__init__.py
touch subdaemon/cli/__init__.py

# 4. Create the core module files
touch subdaemon/config/defaults.py
touch subdaemon/core/engine.py
touch subdaemon/core/resolver.py
touch subdaemon/core/prober.py
touch subdaemon/sources/sources.py
touch subdaemon/output/writer.py
touch subdaemon/cli/main.py
touch subdaemon/cli/display.py

# 5. Create setup.py (essential for 'pip install -e .')
if [ ! -f setup.py ]; then
    echo "📜 Generating setup.py..."
    cat <<EOF > setup.py
from setuptools import setup, find_packages

setup(
    name="subdaemon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "aiohttp",
        "aiodns",
    ],
    entry_points={
        'console_scripts': [
            'subdaemon=subdaemon.cli.main:main',
        ],
    },
)
EOF
fi

# 6. Verify the result
echo -e "\n✅ Structure complete! Current Tree:\n"
find subdaemon -type f -name "*.py" | sort

echo -e "\n🚀 Next steps:"
echo "1. chmod +x build_project.sh"
echo "2. pip install -e ."
