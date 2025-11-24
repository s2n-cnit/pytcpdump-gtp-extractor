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

> [!TIP]
> Once activated, you can execute profiled-swarm.py directly, knowing that all required packages are available and properly configured.

## Usage

Run the the main script.

```shell
python pytcpdump-gtp-generator.py -i eth0 -i eth2 -f 'icmp' -w test.pcap -l -p /home/ubuntu/ -s 192.168.13.3 -o 22 -u ubuntu -a password
.
```

> [!TIP]
> Use the -h|-help flag for additional command-line options:

```shell
python pytcpdump-gtp-extractor.py --h

# or

python pytcpdump-gtp-extractor.py --help

# Example Output:
# usage: pytcpdump-gtp-extractor.py [OPTIONS]
#
# Captures network traffic on specified interfaces with an optional filter and save to the file if provided.
#
# Options:
#   -i, --iface=STR                  interfaces to sniff the traffic.
#   -f, --filter=STR                 tcpdump / bpf filter. (default: no filter)
#   -w, --output=STR                 output pcap file to save captured packets.
#   -d, --duration=INT               duration of the capture in seconds (0 = infinite). (default: 0)
#   -l, --logging                    enable logging of captured packets.
#   -p, --move-to-scp-path=STR       SCP path to move the output pcap after capture.
#   -s, --move-to-scp-server=STR     SCP server address.
#   -o, --move-to-scp-port=STR       SCP server port.
#   -u, --move-tp-scp-username=STR   SCP username.
#   -a, --move-to-scp-password=STR   SCP password.
#   -m, --move-to-nfs-path=STR       move the output pcap to NFS path after capture.

# Other actions:
#   -h, --help                       Show the help
```

# License

> [!NOTE]
> This project is licensed under the **MIT** License.

> [!TIP]
> See the LICENSE file for details.

[^1]: GPRS Tunneling Protocol
