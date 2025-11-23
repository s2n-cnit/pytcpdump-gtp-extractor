# PyTCPDump GTP Extractor

> Simple version of tcpdump developed using Python and scapy that enable the extraction of GPT-U tunnel encapsulation

## Overview

This is a **Python program** built to help analyze network traffic. Its main job is to read files containing **packet captures** (like `.pcap` or `tcpdump` files) and specifically pull out information related to the
**GTP**[^1]. This protocol is crucial for carrying user data within mobile networks (like 3G and 4G). The tool makes it easier to inspect mobile network data by isolating and presenting the key GTP details.

> [!NOTE]
This project appears to use _poetry_ for dependency management, which is the recommended installation method.

> [!TIP]
_Poetry_ provides robust dependency resolution and environment isolation, ensuring that the project runs consistently across different machines without conflicts with other _Python_ projects.

## Prerequisites

- Python 3.11+
  The project leverages modern Python features and requires a stable 3.11 or newer environment.
- Poetry
  Install globally:

```shell
pip install poetry
```

> [!WARNING]
> If you prefer a platform-specific installer, consult the official _Poetry_ documentation.

## Setup

1. Clone the repository:

```shell
git clone [https://github.com/s2n-cnit/pytcpdump-gtp-extractor.git](https://github.com/s2n-cnit/pytcpdump-gtp-extractor.git)
cd pytcpdump-gtp-extractor
```

2. Install dependencies using Poetry:

```shell
poetry install
```

> [!TIP]
> This command reads the _pyproject.toml_ file, fetches all necessary dependencies (including core libraries like Scapy for packet crafting), and installs them into a clean, isolated virtual environment.

3. Activate the virtual environment:

   ```shell
   poetry shell
   ```

    Once activated, you can execute profiled-swarm.py directly, knowing that all required packages are available and properly configured.

## Usage

1. Run the GeneratorExecute the main script.

> [!NOTE]
> The script will initialize the Manager, load the configurations, and start the swarm of traffic generators as parallel worker processes.

```shell
python profiled-swarm.py --config manager.toml.
```

> [!IMPORTANT]
> Upon execution, the Manager will print its status, and each running generator will log its activity, including the start time, the profile it is executing, and any errors encountered during packet transmission.

> [!TIP]
> Use the --help flag for additional command-line options:

```shell
python profiled-swarm.py --help

# Example Output:
# usage: pytcpdump-gtp-extractor.py [-h]
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --config CONFIG_PATH  Specify the path to the manager configuration file. (default: manager.toml)
```

# License

> [!NOTE]
> This project is licensed under the **MIT** License.

> [!TIP]
> See the LICENSE file for details.


[^1]: GPRS Tunneling Protocol
