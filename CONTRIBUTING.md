# Contributing to Learn Scapy

First off, thank you for considering contributing to Learn Scapy! It's people like you that make this a great learning resource for the cybersecurity community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Guidelines](#development-guidelines)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Python and Scapy versions**
- **Operating system** and version
- **Error messages** or screenshots

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** - why is this enhancement needed?
- **Proposed solution** or implementation ideas
- **Examples** of how it would work

### Adding Examples

We welcome new examples! When adding code examples:

1. **Choose the right level**: Basic, Intermediate, Advanced, or Projects
2. **Follow existing structure**: Look at similar examples
3. **Include documentation**: Add comments and README entries
4. **Test thoroughly**: Ensure code works as expected
5. **Add warnings**: Include ethical/legal warnings where needed

### Improving Documentation

Documentation improvements are always welcome:

- Fix typos or clarify confusing sections
- Add missing information
- Update outdated content
- Improve formatting or organization
- Add diagrams or illustrations

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/learn-scapy.git
   cd learn-scapy
   ```

3. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Guidelines

### Code Examples

When creating code examples:

1. **Use clear, descriptive names** for variables and functions
2. **Add comprehensive comments** explaining what each section does
3. **Include docstrings** for all functions and classes
4. **Handle errors gracefully** with try-except blocks
5. **Check for root/admin privileges** when needed
6. **Add usage examples** in comments or docstrings
7. **Include ethical warnings** for potentially dangerous code

Example template:
```python
#!/usr/bin/env python3
"""
Script Name: example_script.py
Description: Brief description of what this script does
Author: Your Name
Date: YYYY-MM-DD

WARNING: This script requires root/administrator privileges.
         Only use on networks you own or have permission to test.

Usage:
    sudo python3 example_script.py
"""

from scapy.all import *
import sys

def main():
    """Main function with error handling."""
    try:
        # Your code here
        pass
    except PermissionError:
        print("Error: This script requires root/administrator privileges")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Documentation

When writing documentation:

1. **Use clear, simple language** - assume readers are learning
2. **Include examples** wherever possible
3. **Add code snippets** with syntax highlighting
4. **Structure with headers** for easy navigation
5. **Link to related sections** and resources
6. **Include prerequisites** and dependencies

### Project Structure

When adding new content:

```
learn-scapy/
├── examples/
│   ├── 01-basic/           # Beginner examples
│   ├── 02-intermediate/    # Intermediate examples
│   ├── 03-advanced/        # Advanced examples
│   └── 04-projects/        # Complete projects
├── docs/                   # Documentation
├── exercises/              # Practice exercises
│   ├── beginner/
│   ├── intermediate/
│   ├── advanced/
│   └── solutions/
└── resources/              # Reference materials
```

## Submitting Changes

1. **Test your changes** thoroughly:
   ```bash
   python3 -m py_compile your_script.py  # Check syntax
   python3 your_script.py                 # Test functionality
   ```

2. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add: Brief description of changes"
   ```

   Use conventional commit messages:
   - `Add:` for new features or files
   - `Fix:` for bug fixes
   - `Update:` for modifications to existing content
   - `Docs:` for documentation changes
   - `Style:` for formatting changes

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create a Pull Request**:
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Fill in the PR template with details
   - Submit the PR

### Pull Request Guidelines

- **Title**: Clear, descriptive title
- **Description**: Explain what changes you made and why
- **Reference issues**: Link related issues (#issue_number)
- **Screenshots**: Include for UI/output changes
- **Testing**: Describe how you tested the changes
- **Documentation**: Update docs if needed

## Style Guidelines

### Python Code Style

Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/):

- **Indentation**: 4 spaces (not tabs)
- **Line length**: Maximum 100 characters
- **Imports**: Group standard library, third-party, and local imports
- **Naming conventions**:
  - Functions/variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_CASE`

### Documentation Style

- Use **Markdown** for all documentation
- Use **code blocks** with language specification
- Use **headers** for organization (h1 for title, h2 for sections)
- Use **lists** for steps or multiple items
- Use **bold** for emphasis, **italic** for technical terms

### Commit Messages

Good commit message:
```
Add: Basic sniffing example with filtering

- Created basic_sniffing.py with packet capture example
- Added filtering by protocol and port
- Included safety warnings and permission checks
- Updated README with usage instructions
```

Bad commit message:
```
updated files
```

## Security and Ethics

### Important Guidelines

- **Always include warnings** about legal and ethical use
- **Never encourage illegal activities** in code or documentation
- **Emphasize permission requirements** for network operations
- **Suggest safe testing environments** (isolated networks, VMs)
- **Report security vulnerabilities** responsibly

### Sensitive Information

- **Never commit** passwords, API keys, or tokens
- **Never commit** real network captures with sensitive data
- **Sanitize examples** to remove identifying information
- **Use example domains** (example.com, test.local)

## Questions?

- **Open an issue** for questions about contributing
- **Join discussions** in GitHub Discussions
- **Check existing issues and PRs** for similar work

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- Release notes for significant contributions
- README acknowledgments section (for major contributions)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Learn Scapy! Together we make network security education better for everyone! 🚀**
