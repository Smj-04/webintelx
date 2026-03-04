from setuptools import setup, find_packages

# read requirements
with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line and not line.startswith("#")]

setup(
    name="phishing_detection",
    version="0.1",
    description="Machine learning based phishing URL detection system",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phishdetect=phishing.main:run_cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
