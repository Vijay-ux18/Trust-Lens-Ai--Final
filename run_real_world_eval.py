"""CLI entry point for TrustLens AI real-world multi-format validation."""

import argparse
import json

from btech.real_world_evaluation import evaluate_directory


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statically evaluate TrustLens multi-format model on labelled real-world files."
    )
    parser.add_argument(
        "--dataset",
        default="data/real_world_dataset",
        help="Directory containing benign/ and malicious/ subdirectories.",
    )
    parser.add_argument(
        "--output",
        default="data/real_world_evaluation",
        help="Directory for metrics.json and file_results.csv.",
    )
    args = parser.parse_args()

    metrics = evaluate_directory(args.dataset, args.output)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
