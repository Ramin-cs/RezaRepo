#!/usr/bin/env python3
"""
Setup script for Advanced XSS Scanner
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="advanced-xss-scanner",
    version="1.0.0",
    author="AI Assistant",
    author_email="ai@example.com",
    description="Advanced XSS Scanner with complete reconnaissance and exploitation capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/advanced-xss-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "xss-scanner=xss_scanner:main",
        ],
    },
    keywords="xss, security, vulnerability, scanner, web, penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/example/advanced-xss-scanner/issues",
        "Source": "https://github.com/example/advanced-xss-scanner",
        "Documentation": "https://github.com/example/advanced-xss-scanner/wiki",
    },
)