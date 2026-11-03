"""
Demo Server for Jury Presentation
=================================
Lightweight, zero-dependency HTTP and REST API server.
Serves the interactive Jury Dashboard and connects directly to the
Python ClosedLoopSimulationEngine.

Usage:
  python3 demo_server.py [--port 8080]
"""

import http.server
import json
import os
import socketserver
import sys
import urllib.parse
from typing import Dict

from closed_loop_engine import ClosedLoopSimulationEngine

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class JuryDemoRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handles static files and simulation REST endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.path = "/dashboard.html"
            return super().do_GET()

        elif path == "/api/run-simulation":
            # Query parameters: strategy, samples
            query = urllib.parse.parse_qs(parsed.query)
            strategy = query.get("strategy", ["balanced_mixture"])[0]
            samples = int(query.get("samples", ["1500"])[0])

            engine = ClosedLoopSimulationEngine(retraining_strategy=strategy, seed=42)
            report = engine.run_simulation(total_samples=samples)

            # Return top events and summary metrics
            response_data = {
                "summary": report,
                "adwin_triggers": engine.adwin_triggers,
                "retraining_events": engine.retraining_events,
                "recent_events": engine.events_log[-100:]  # last 100 events
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        elif path == "/api/benchmarks":
            benchmark_file = os.path.join(DIRECTORY, "benchmark_results.json")
            if os.path.exists(benchmark_file):
                with open(benchmark_file, "r") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
            return

        return super().do_GET()

def run_server(port: int = PORT):
    # Allow port reuse to avoid 'Address already in use' during quick re-runs
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), JuryDemoRequestHandler) as httpd:
        print("=" * 76)
        print(" ADAPTIVE DDoS DRIFT RETRAINING | JURY DEMONSTRATION SERVER ")
        print("=" * 76)
        print(f" [✓] Server running at: http://localhost:{port}")
        print(f" [✓] Direct Dashboard : http://localhost:{port}/dashboard.html")
        print(f" [✓] Serving files from: {DIRECTORY}")
        print(" Press Ctrl+C to stop the server.")
        print("=" * 76)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
            httpd.shutdown()

if __name__ == "__main__":
    port_arg = PORT
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port_arg = int(sys.argv[1])
    run_server(port_arg)

