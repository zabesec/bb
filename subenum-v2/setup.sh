#!/usr/bin/env bash

set -e

echo "Building Docker images..."
docker compose build

echo "Starting database..."
docker compose up -d subenum-db

echo "Waiting for database to be ready..."
sleep 5

echo "Installing Python dependencies..."
pip3 install -r requirements.txt

echo "Making wrapper executable..."
chmod +x subenum

echo "Creating necessary directories..."
mkdir -p config wordlists

echo "Starting scheduler..."
docker compose up -d subenum-scheduler

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit config.yml with your settings"
echo "2. Place wordlists in ./wordlists/"
echo "3. Run: subenum -d example.com"
