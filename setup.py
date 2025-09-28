from setuptools import setup, find_packages

setup(
    name="cybershield-ai",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "streamlit>=1.28.0",
        "numpy>=1.23.5",
        "pandas>=1.5.3",
        "scikit-learn>=1.2.2",
        "requests>=2.28.2",
        "python-jose>=3.3.0",
        "cryptography>=39.0.2",
        "pycryptodome>=3.18.0",
        "urllib3>=1.26.15",
        "python-dotenv>=0.19.0"
    ],
    python_requires=">=3.8",
)
