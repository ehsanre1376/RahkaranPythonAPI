from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="rahkaran-api",
    version="0.1.0",
    author="Ehsan Rezaei",
    author_email="your.email@example.com",  # Replace with your email
    description="A Python client for the Rahkaran API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/rahkaran-api",  # Replace with your repo URL
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "rsa>=4.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.0.0",
            "black>=20.8b1",
            "isort>=5.0.0",
            "flake8>=3.9.0",
            "mypy>=0.800",
        ],
    },
) 