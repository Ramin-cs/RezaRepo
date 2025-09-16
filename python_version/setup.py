#!/usr/bin/env python3
"""
Setup script for Advanced Bug Bounty Tool
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="advanced-bug-bounty-tool",
    version="1.0.0",
    author="Security Researcher",
    author_email="security@example.com",
    description="A comprehensive reconnaissance and vulnerability scanning tool for bug bounty hunters",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/advanced-bug-bounty-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "bug-bounty-tool=main:main",
        ],
    },
    keywords="security, bug-bounty, reconnaissance, vulnerability-scanning, xss, sql-injection, open-redirect",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/advanced-bug-bounty-tool/issues",
        "Source": "https://github.com/yourusername/advanced-bug-bounty-tool",
        "Documentation": "https://github.com/yourusername/advanced-bug-bounty-tool#readme",
    },
)