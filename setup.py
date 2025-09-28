#!/usr/bin/env python3
"""
Setup script for Open Redirect Scanner
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="open-redirect-scanner",
    version="1.0.0",
    author="Security Researcher",
    author_email="researcher@example.com",
    description="Advanced Open Redirect Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/open-redirect-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "open-redirect-scanner=open_redirect_scanner:main",
        ],
    },
    keywords="security, vulnerability, scanner, open-redirect, penetration-testing, bug-bounty",
    project_urls={
        "Bug Reports": "https://github.com/example/open-redirect-scanner/issues",
        "Source": "https://github.com/example/open-redirect-scanner",
        "Documentation": "https://github.com/example/open-redirect-scanner/wiki",
    },
)