# Contributing to TrustLens AI

First off, thank you for considering contributing to TrustLens AI! It's people like you who make open source such an amazing community.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct (detailed in [README.md](README.md)).

## How Can I Contribute?

### Reporting Bugs
If you find a bug, please create a GitHub Issue. When reporting a bug, please include:
- Your operating system and Python version.
- The exact steps to reproduce the issue.
- Expected vs. actual behavior.
- Any relevant logs or error stack traces.

### Suggesting Enhancements
We welcome feature suggestions! Please submit an Issue detailing:
- The core problem this enhancement solves.
- A clear description of the proposed behavior/feature.
- Alternatives you've considered.

### Submitting Pull Requests (PRs)
1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Install the development packages:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Make your changes, keeping coding standards in mind.
4. Format and lint your changes:
   ```bash
   black src/ tests/
   isort src/ tests/
   flake8 src/
   ```
5. Ensure the entire test suite passes:
   ```bash
   PYTHONPATH=src pytest
   ```
6. Commit your changes using Conventional Commits guidelines (e.g., `feat(analyzer): add YARA rule parsing`).
7. Open a Pull Request against our `main` branch.

## Commit Message Guidelines

We enforce the **Conventional Commits** specification. Commit messages should follow this format:

```text
<type>(<scope>): <description>

[optional body]
```

- **feat**: A new feature (e.g., `feat(analyzer): support APK scanning`)
- **fix**: A bug fix (e.g., `fix(predict): correct overall file entropy false positives`)
- **docs**: Documentation changes (e.g., `docs(readme): add installation steps`)
- **style**: Code style changes (formatting, missing semi-colons, etc.)
- **refactor**: Code changes that neither fix a bug nor add a feature
- **test**: Adding missing tests or correcting existing ones
- **chore**: Build processes, dependency updates, or auxiliary tool configurations

Thank you for contributing!
