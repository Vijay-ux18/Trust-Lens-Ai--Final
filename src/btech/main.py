"""
Module 4: Main Application & CLI Entrypoint.
Provides a unified command-line interface for TrustLens AI to train the model,
scan local executable files, or start the Streamlit web UI.
"""

import json
import os
import sys
from typing import List

from btech.pipeline import run_pipeline
from btech.predict import TrustLensPredictor


def print_usage() -> None:
    """Print command line usage details."""
    print("TrustLens AI - Command Line Tool")
    print("Usage:")
    print("  python -m btech.main train           Train the machine learning model")
    print("  python -m btech.main scan <file>     Perform static security scan on a file")
    print("  python -m btech.main ui              Start the Streamlit Web Application")


def handle_scan(file_path: str) -> None:
    """Read file and print static threat scan results in JSON format."""
    if not os.path.exists(file_path):
        print(json.dumps({"error": f"File not found: {file_path}"}, indent=2))
        sys.exit(1)

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        predictor = TrustLensPredictor()
        predictor.load_assets()

        result = predictor.predict_file(file_bytes)

        # Clean results for printout (exclude raw features to keep CLI output clean)
        print_res = {
            "file": os.path.basename(file_path),
            "prediction": result["prediction"],
            "trust_score": result["trust_score"],
            "risk_level": result["risk_level"],
            "confidence": result.get("confidence", 75.0),
            "explanations": result.get("rule_explanations", []),
            "is_simulated_mode": result["is_mock"],
        }

        print(json.dumps(print_res, indent=2))

    except Exception:
        print(json.dumps({"error": "Scan failed due to an internal error."}, indent=2))
        sys.exit(1)


def handle_ui() -> None:
    """Launch the Streamlit web interface using subprocess execution."""
    import subprocess

    app_path = os.path.join(os.path.dirname(__file__), "app.py")
    print(f"Launching Streamlit Web App from {app_path}...")
    try:
        subprocess.run(["streamlit", "run", app_path], check=True)
    except KeyboardInterrupt:
        print("\nStreamlit server stopped.")
    except Exception as e:
        print(f"Failed to start Streamlit: {e}")
        sys.exit(1)


def main(args: List[str]) -> None:
    """Parse CLI arguments and dispatch commands."""
    if len(args) < 1:
        print_usage()
        sys.exit(1)

    cmd = args[0].lower()

    if cmd == "train":
        print("Starting Machine Learning Training Pipeline...")
        run_pipeline()
    elif cmd == "scan":
        if len(args) < 2:
            print("Error: Missing target file path.")
            print("Usage: python -m btech.main scan <filepath>")
            sys.exit(1)
        handle_scan(args[1])
    elif cmd == "ui":
        handle_ui()
    else:
        print(f"Unknown command: {cmd}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
