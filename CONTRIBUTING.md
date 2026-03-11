# Contributing to KEIP

Thank you for your interest in contributing to KEIP! We welcome contributions from the community to make software supply chain security better for everyone.

## How to Contribute

### Reporting Bugs
If you find a bug, please create a GitHub issue with the following details:
- Steps to reproduce the bug.
- Expected behavior vs. actual behavior.
- Your environment (OS, Kernel version, Python version).

### Suggesting Enhancements
We love new ideas! Please open an issue to discuss your feature request before starting work to ensure it aligns with the project roadmap.

### Pull Requests
1.  Fork the repository.
2.  Create a new branch for your feature or fix (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

## Development Setup

To set up your development environment:

```bash
# install dependencies
sudo ./setup.sh

# Run locally
sudo ./run_keip.sh
```

## Code Style
- Follow PEP 8 for Python code.
- Ensure shell scripts are POSIX compliant where possible.
- Add comments for complex eBPF logic.

## License
By contributing, you agree that your contributions will be licensed under the MIT License.
