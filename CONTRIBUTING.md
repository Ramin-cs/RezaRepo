# Contributing to Open Redirect Scanner

Thank you for your interest in contributing to the Open Redirect Scanner project! This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows a code of conduct that we expect all contributors to follow. Please be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or bugfix
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

1. Install dependencies:
```bash
make install
# or
pip install -r requirements.txt
```

2. Install the package in development mode:
```bash
make setup
# or
pip install -e .
```

3. Run tests:
```bash
make test
# or
python test_scanner.py
```

## Contributing Guidelines

### Bug Reports

When reporting bugs, please include:
- Clear description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, etc.)
- Log files if available

### Feature Requests

When requesting features, please include:
- Clear description of the feature
- Use case and motivation
- Proposed implementation approach (if you have one)
- Any potential drawbacks or considerations

### Code Contributions

When contributing code:

1. **Follow the existing code style**
2. **Add tests for new functionality**
3. **Update documentation as needed**
4. **Ensure all tests pass**
5. **Add appropriate logging**
6. **Handle errors gracefully**

### Pull Request Process

1. **Create a descriptive title**
2. **Provide a clear description of changes**
3. **Reference any related issues**
4. **Ensure all tests pass**
5. **Update documentation if needed**
6. **Request review from maintainers**

## Code Style

- Use Python 3.8+ features
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write clear, descriptive variable and function names
- Add docstrings for all public functions
- Use meaningful commit messages

## Testing

- Write tests for new functionality
- Ensure existing tests still pass
- Test edge cases and error conditions
- Use appropriate test data
- Mock external dependencies when possible

## Documentation

- Update README.md for user-facing changes
- Update docstrings for code changes
- Add examples for new features
- Update CHANGELOG.md for significant changes

## Security Considerations

- Never include sensitive information in code
- Follow secure coding practices
- Consider security implications of changes
- Report security issues privately to maintainers

## Areas for Contribution

- **New WAF bypass techniques**
- **Additional payload types**
- **Performance improvements**
- **Better error handling**
- **Enhanced reporting features**
- **Additional injection point types**
- **Improved Chrome automation**
- **Better logging and debugging**
- **Documentation improvements**
- **Test coverage improvements**

## Questions?

If you have questions about contributing, please:
- Open an issue with the "question" label
- Contact the maintainers
- Check existing issues and discussions

## Thank You!

Your contributions help make this project better for everyone. We appreciate your time and effort!