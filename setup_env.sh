#!/bin/bash
echo "🚀 Setting up netsim environment..."

# Optional: create venv
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate it
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
echo "📥 Installing dependencies from requirements.txt..."
pip install -r requirements.txt

echo "✅ Done! Activate with: source venv/bin/activate"
echo "Then run with: sudo python -m netsim"