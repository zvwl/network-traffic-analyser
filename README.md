# Network Traffic analyser

## Overview
The **Network Traffic analyser** is a terminal-based tool designed to capture and filter network packets (TCP, UDP, ICMP). With a hacker-inspired interface, it offers a customizable and intuitive experience for analysing network traffic.

## Features
- **Protocol-based filtering**: Easily filter packets based on TCP, UDP, ICMP protocols.
- **Port-based filtering**: Focus on specific port traffic to narrow down your analysis.
- **Real-time packet capture**: Capture and display network traffic live from your terminal.
- **Customizable terminal interface**: Built for ease of use with an ASCII art-driven UI to enhance the user experience.

## Requirements
Ensure you have the following installed:
- Python 3.x
- `pip`
- `virtualenv` (Optional, for creating isolated environments)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/zvwl/network-traffic-analyser.git
    cd network-traffic-analyser
    ```

2. Create a virtual environment and activate it:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Run the setup script to install necessary dependencies and initialize the environment:
    ```bash
    make setup
    ```

## Usage

Once installed, you can start capturing traffic using the command:

```bash
python src/analyser.py

```
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


