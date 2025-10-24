#!/usr/bin/env python3
"""
Setup script for Advanced Subdomain Enumeration Tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="subdomain-enumeration-tool",
    version="2.0.0",
    author="Security Researcher",
    author_email="researcher@example.com",
    description="Advanced Subdomain Enumeration Tool with HTTP/HTTPS Probing & Premium APIs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/subdomain-enumeration-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "subdomain-enum=subdomains:main",
        ],
    },
    keywords="subdomain, enumeration, security, penetration-testing, reconnaissance",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/subdomain-enumeration-tool/issues",
        "Source": "https://github.com/yourusername/subdomain-enumeration-tool",
    },
)