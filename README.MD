# NETSIM
Netsim is a fully interactive traffic generation tool.
Highly configurable, netsim allows the user to call and script pre-built patterns or easily extend the tool to support their own with minimal additional code.
The tool uses a threaded approach, spining up threads for each pattern that will execute at the same time.
Currently the tool will scale itself to the size of the machine, and may take most if not all of your system CPU and RAM to run depending on what you ask it to do.

Netsim's interactive shell allows the user, even in the middle of pre-scripted generation, to start/stop any known pattern in the system.
An intuitive, language like command structure `start pattern_y in 30 loop 10` allows for fast changes with approacable verbiage.  

-----------------

## Usecases
#### Testing
- Network firewall rules
- Route policy
- Simulate DDoS detection (non-volumetrically)
- Validate operation of other tools 
#### AI Training

- Generate high quality synthetic traffic for the training of AI models
  - threaded interactive approach allows for real-time adjustment by other code, or other models, to help automate more of your training optimization efforts  

#### Impressing friends and family

- ymmv

-----------------

# Features
### Current
Netsim currently supports basic interactive pattern launching, and scheduling.  
There is a limited set of partially developed patterns, but the logic exists to build this out further.
Netsim can pick IP's from consumer, service, and cdn blocks to use when specifying flow types.
### Future Plans
- Complete a substantial library of patterns using as many generic function steps as possible for re-use by others with new patterns in the future.
- Enhanced scheduling options, ability to control concurrency in case of misconfiguration
- "All the options" config files: currently there are a few dozen settings that are found in the code and either not configurable easily, or not exposed in the YAML
- Support additional generation modes
   - PCAP replay
   - PCAP marge / stretch
   - PCAP packet value "Fuzzing"
- On-the-fly patterning (a pcap like terminology used to generate ad-hoc without yaml)
   - Programatic entrypoint for the same, for use by other models or code
- Output mode of direct-PCAP
- Interface interactive selection and interface selection inclusion in patterns

----------------

# Installation and Basic Use

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
## Settings found in \_\_main\_\_.py
``` run_mode_ = "yaml+interactive"
    speed_mode_ = True
    output_mode_ = "send"
    iface_ = "lo"
```
Your interface name must match the system name.  lo by default, but that could present issues.
Not all loopbacks can handle layer 3 packet writing in the method we utilize here, currently.

---

## 📦 Project Structure

```text
├── config
│   └── simulation_config.yaml
├── __main__.py
├── netsim
│   ├── controller.py                           # manages interactive, non-scripted, generation
│   ├── core
│   │   ├── launch_spec.py
│   │   └── sender_pool.py
│   ├── engine.py
│   ├── helper_wrapper.py
│   ├── internet_properties.py
│   ├── launch
│   │   ├── __init__.py
│   │   └── runner.py
│   ├── logger
│   │   ├── global_logger.py
│   │   ├── __init__.py
│   │   └── netsim_logging_manager.py
│   ├── __main__.py
│   ├── orchestrator.py                         # manages timed, scripted generation
│   ├── pattern_registry.py
│   ├── patterns                                # patterns are created and referenced here
│   │   ├── base.py
│   │   ├── __init__.py
│   │   ├── patterns.py
│   │   └── pattern_tracker.py
│   ├── state                                   # Various state machines to help differentiate conversation types
│   │   ├── bgp_fsm.py
│   │   ├── gre_fsm.py
│   │   ├── http_fsm.py
│   │   ├── __init__.py
│   │   ├── ipsec_fsm.py
│   │   ├── quic_fsm.py
│   │   ├── smtp_fsm.py
│   │   ├── ssh_fsm.py
│   │   ├── tcp_fsm.py
│   │   └── udp_fsm.py
│   └── utils.py
├── README.MD
├── requirements.txt
├── run_netsim.sh
├── setup_env.sh
├── setup.py
└── test_import.py

```
---
## Patterns

Patterns can reference and use one or more state machines, as needed, but it is not required.  
These can be as simple as several hard-coded packet values in order - if that's what you want. 
The state machine classes exist to provide a method of enforcing normal conversational behavior, but can be tweaked to enforce abnormal behavior as well.

- When creating new patterns keep with the existing function format and there should be no issues. 
- Remember to add new patterns to the pattern registry as well after creation, or you won't be able to call them by name or in the timeline. 
- Remember to update your help files with the new pattern names as they are created.

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
---

## CLI Environment
Netsim runs an interactive shell (provided this is not disabled) which will appear as soon as you run the tool.
Sample output and commands:

```netsim> Type 'help' for commands.
  netsim> help
  Available commands:
    start <pattern_id> [in <s>] [for <s> | loop <n>] [flow <type>] - Launch pattern (use either 'for' or 'loop', not both)
        list                              - Show available pattern IDs
        start                             - See command structure above
        stop all                          - Stop all running patterns
        stop <pattern_id>                 - Stop a running pattern
  
        status                            - Show thread status
        status <s>                        - Post thread status every <s> seconds
        stop status                       - Stop the status monitor
  
        test all patterns                 - Moves through all available patterns and attempts every CLI combination
  
        help                              - Show this help
        exit                              - Exit the simulator
  
      Valid flow types:
        consumer_to_consumer, consumer_to_cdn, consumer_to_service, cdn_to_consumer, cdn_to_cdn, cdn_to_service, service_to_consumer, service_to_cdn, service_to_service
      
  netsim> list
  Available patterns:
    - bgp
    - dns_normal
    - fsm_bgp_session
    - fsm_gre_tunnel
    - fsm_http
    - fsm_https
    - fsm_ipsec_tunnel
    - fsm_quic_stream
    - fsm_ssh
    - fsm_tcp_session
    - fsm_udp_session
    - gre
    - https_web_browse
    - icmp_unreachable
    - ipsec_isakmp
    - ntp
    - quic_video
    - snmp
    - ssh
    - tcp_handshake
    - udp_dns_frag
  
  Valid flow types:
    - cdn_to_cdn
    - cdn_to_consumer
    - cdn_to_service
    - consumer_to_cdn
    - consumer_to_consumer
    - consumer_to_service
    - service_to_cdn
    - service_to_consumer
    - service_to_service
```

---

## 🛠 Troubleshooting

- 
---

## 📬 Feedback & Contributions

We welcome feedback and contributions! 

Please open an issue or submit a pull request on GitHub and remember the the license terms when doing so.

We are especially looking for help with making better state machines / pattern related additions at this time.

---
## 🛡 License

This project is dual-licensed:

- **CC BY-NC 4.0** for non-commercial use (research, education, internal testing)
- **Commercial license required** for resale, SaaS, integration, or monetized use of any kind

See [LICENSE.md](./LICENSE.md) for full terms.