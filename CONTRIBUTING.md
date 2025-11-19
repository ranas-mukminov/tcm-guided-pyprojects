# Contributing Guidelines

Thank you for your interest in contributing to TCM Guided Python Security Projects!

## Code Style

### Python Standards
- Follow **PEP 8** style guide strictly
- Use **4 spaces** for indentation (no tabs)
- Maximum line length: **79 characters** for code, **72 for comments**
- Use **type hints** where possible for better code clarity
- Add **comprehensive docstrings** to all functions and classes
- Include **error handling and validation** for all user inputs
- Add **security warnings** where appropriate for potentially dangerous operations

### Documentation
- Write clear, concise docstrings following Google or NumPy style
- Include parameter descriptions and return types
- Add usage examples in docstrings for complex functions
- Update README.md if adding new tools or major features
- Keep both English and Russian documentation in sync

### Security Considerations
- **Never commit secrets, API keys, or credentials**
- Add `.env` files to `.gitignore` for sensitive configuration
- Include **educational warnings** in tools that could be misused
- Implement **input validation** to prevent injection attacks
- Use **parameterized queries** for any database operations
- Add **rate limiting** where appropriate to prevent abuse

## Pull Request Process

### Before Submitting

1. **Fork the repository** to your GitHub account
2. **Create a feature branch** with a descriptive name:
   ```bash
   git checkout -b feature/amazing-feature
   ```
   or
   ```bash
   git checkout -b fix/bug-description
   ```

3. **Make your changes** with clear, atomic commits
4. **Test thoroughly** - ensure your changes work as expected
5. **Run linters** to ensure code quality:
   ```bash
   # Install development dependencies
   pip install flake8 pylint black bandit

   # Run linters
   flake8 *.py
   pylint *.py
   black --check *.py
   bandit -r *.py
   ```

6. **Update documentation** as needed
7. **Add tests** if adding new functionality (when applicable)

### Submitting the PR

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/amazing-feature
   ```

2. **Open a Pull Request** with:
   - Clear, descriptive title
   - Detailed description of changes
   - Reference to related issues (if any)
   - Screenshots/examples if applicable

3. **Respond to feedback** - be open to suggestions and iterate on your code

## Commit Conventions

Follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code formatting, no functional changes
- **refactor**: Code refactoring without changing functionality
- **test**: Adding or updating tests
- **chore**: Maintenance tasks
- **security**: Security improvements or fixes
- **perf**: Performance improvements

### Examples
```bash
feat(scanner): add multi-threaded port scanning
fix(ssh): correct timeout handling in brute force
docs: update README with new installation steps
security: add input validation to prevent injection
refactor(hasher): improve SHA256 cracking efficiency
chore: update dependencies to latest versions
```

## Code Review

All submissions require review before merging:

- **Be patient** - maintainers review PRs as time permits
- **Be receptive** to feedback and willing to make changes
- **Discuss** significant design decisions before implementation
- **Keep PRs focused** - one feature or fix per PR
- **Test thoroughly** before marking PR as ready for review

## Testing Guidelines

While comprehensive test suites are not required, please:

- **Manually test** your changes thoroughly
- **Verify** no existing functionality is broken
- **Test edge cases** and error conditions
- **Document** how to test the changes in the PR description

## Community Guidelines

### Be Respectful
- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community

### Educational Focus
- Tools must remain **educational in nature**
- Include proper **disclaimers** for security tools
- Emphasize **authorized testing only**
- Follow **ethical hacking** principles
- Promote **responsible disclosure** of vulnerabilities

### Prohibited Content
- No tools designed solely for malicious purposes
- No bypass tools for legitimate security measures (without educational context)
- No credential stealers or keyloggers
- No tools that violate privacy or laws
- No plagiarized code or content

## Getting Help

- Open an **[Issue](https://github.com/ranas-mukminov/tcm-guided-pyprojects/issues)** for questions
- Check existing issues and PRs first to avoid duplicates
- Provide detailed information when reporting bugs:
  - Python version
  - Operating system
  - Steps to reproduce
  - Expected vs actual behavior
  - Error messages/logs

## Professional Services

For professional security consulting, penetration testing, or infrastructure services:

**[run-as-daemon.ru](https://run-as-daemon.ru)** - Professional DevOps, System Administration & Security Services

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Project documentation (for significant contributions)
- Special mention for security vulnerability reports

## Questions?

Feel free to reach out by opening an issue or contacting via [run-as-daemon.ru](https://run-as-daemon.ru).

Thank you for contributing to the security education community! 🔒
