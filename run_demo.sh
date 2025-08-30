#!/bin/bash
# Quick demo script for Advanced XSS Scanner

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Advanced XSS Scanner                      ║"
echo "║                       Quick Demo                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found!"
    exit 1
fi

echo "🚀 Starting demo vulnerable server..."
python3 demo.py -p 8080 &
DEMO_PID=$!

# Wait for server to start
sleep 3

echo ""
echo "🔍 Running XSS Scanner against demo server..."
echo "Target: http://localhost:8080"
echo ""

# Run scanner with demo settings
python3 advanced_xss_scanner.py -u http://localhost:8080 -d 2 --delay 0.5 -t 3

echo ""
echo "🛑 Stopping demo server..."
kill $DEMO_PID 2>/dev/null

echo "✅ Demo completed!"
echo ""
echo "📄 Check the generated reports:"
echo "  • HTML Report: xss_scan_report_*.html"
echo "  • JSON Report: xss_scan_report_*.json"
echo "  • Screenshots: screenshots/"