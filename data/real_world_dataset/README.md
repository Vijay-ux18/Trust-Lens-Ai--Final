# Real-World Validation Dataset

Place legally obtained, labelled samples here for external validation:

- `benign/` — files independently labelled benign
- `malicious/` — files independently labelled malicious

TrustLens reads these files for **static analysis only** and never executes them.

Do not commit malware samples to the repository. Keep the corpus outside version control
unless the dataset license explicitly permits redistribution.

For reproducibility, record the corpus/source, collection date, number of samples,
supported formats, and label methodology in your project report.

Run:

```bash
PYTHONPATH=src python run_real_world_eval.py
```

The multi-format evaluator excludes PE files because `.exe`, `.dll`, and `.sys` files
are routed to the separate 54-feature PE model.
