from setuptools import setup, find_packages

# Read requirements.txt into a list
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name='netsim',
    version='0.1.0',
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "netsim = netsim.__main__:main",  # Optional if netsim/__main__.py has a main()
        ],
    },
    author="Your Name",
    description="Synthetic network traffic simulation framework",
    python_requires='>=3.8',
)