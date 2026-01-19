#!/bin/bash
# GServer Rust - Server Launch Script

cd /home/versa/gserver-rust

echo "🎮 GServer Rust - Launch Script"
echo "================================"
echo ""
echo "Building server..."
cargo build --release -p gserver-server --bin gserver

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo ""
    echo "Starting server..."
    echo "Press Ctrl+C to stop"
    echo ""
    ./target/release/gserver
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
