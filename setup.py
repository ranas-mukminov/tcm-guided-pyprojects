"""Setup configuration for TCM Guided Python Security Projects."""

from setuptools import setup, find_packages
import os

# Read the long description from README
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
try:
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = "Educational Python security tools from TCM Security Academy"

setup(
    name="tcm-security-tools",
    version="1.0.0",
    author="Ranas Mukminov",
    author_email="contact@run-as-daemon.ru",
    description="Educational Python security tools from TCM Security Academy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ranas-mukminov/tcm-guided-pyprojects",
    packages=find_packages(where=".", exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Education",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.31.0,<3.0.0",
        "paramiko>=3.4.0,<4.0.0",
        "pwntools>=4.11.0,<5.0.0",
        "colorama>=0.4.6,<1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0,<8.0.0",
            "pytest-cov>=4.1.0,<5.0.0",
            "flake8>=7.0.0,<8.0.0",
            "pylint>=3.0.0,<4.0.0",
            "black>=24.0.0,<25.0.0",
            "bandit>=1.7.5,<2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            # Add CLI commands if needed in future
            # "tcm-scan=host_scanner:main",
        ],
    },
    keywords="security pentesting education hacking ctf tcm-security ethical-hacking vulnerability-scanner",
    project_urls={
        "Bug Reports": "https://github.com/ranas-mukminov/tcm-guided-pyprojects/issues",
        "Source": "https://github.com/ranas-mukminov/tcm-guided-pyprojects",
        "Documentation": "https://github.com/ranas-mukminov/tcm-guided-pyprojects/blob/main/MANUAL.md",
        "Professional Services": "https://run-as-daemon.ru",
    },
    include_package_data=True,
    zip_safe=False,
)
