## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/netsim.git
cd netsim
```

### 2. Set Up a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install the Project (via `setup.py`)

The project includes a `setup.py` that reads dependencies from `requirements.txt`. You can install the package in **editable mode** like this:

```bash
pip install -e .
```

This will make the `netsim` package available in your environment for development and testing.


```bash
pip install -e .
```

### 4. Run the Application

Run directly using your raw-socket-capable virtualenv Python:

```bash
.venv/bin/python-rawsocket -m netsim
```

If you haven’t created that binary yet:

```bash
cp /usr/bin/python3.10 .venv/bin/python-rawsocket
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python-rawsocket
```

This avoids needing to run as `sudo` while still allowing raw network operations.

---

## 📦 Project Structure

```text
netsim/
├── netsim/                 # Main package directory
│   ├── __init__.py
│   ├── __main__.py         # Entry point for `python -m netsim`
│   ├── engine.py
│   ├── logger/
│   ├── patterns/
│   ├── state/
│   └── ...                 # Other modules
├── requirements.txt        # List of dependencies
├── setup.py                # Package configuration
└── README.md               # Project documentation
```

---

## ⚙️ setup.py Configuration

```python
from setuptools import setup, find_packages

with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name='netsim',
    version='0.1.0',
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "netsim = netsim.__main__:main",  # Ensure __main__.py has a main() function
        ],
    },
    author="Your Name",
    description="Synthetic network traffic simulation framework",
    python_requires='>=3.8',
)
```

**Note:** Ensure that your `__main__.py` file contains a `main()` function to serve as the entry point.

---

## 📄 requirements.txt

To update your dependencies list from the current environment:

```bash
pip freeze > requirements.txt
```

---

## 🧼 Cleanup

To remove the virtual environment:

```bash
deactivate
rm -rf venv
```

---

## 🛠 Troubleshooting

- **ModuleNotFoundError:** Make sure your virtual environment is activated.
- **Permission Issues:** Avoid `sudo`; use virtual environments to isolate your project.

---

## 📬 Feedback & Contributions

We welcome feedback and contributions! Please open an issue or submit a pull request on GitHub.
