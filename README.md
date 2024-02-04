# Python CICFlowMeter

> This project is not maintained actively by me. If you found something wrong (bugs, incorrect results) feel free to create issues or pull requests.

### Installation

```sh
git clone https://github.com/hieulw/cicflowmeter
cd cicflowmeter
poetry install
```

### Usage

```sh
usage: cicflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) [-c] [-v] output

positional arguments:
  output                output file name (in flow mode) or directory (in sequence mode)

options:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE    capture online data from INPUT_INTERFACE
  -f INPUT_FILE         capture offline data from INPUT_FILE
  -c, --csv             output flows as csv
  -v, --verbose         more verbosity
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow csv: (**need root permission**)

```
cicflowmeter -i eth0 -c flows.csv
```

### References:

1. https://www.unb.ca/cic/research/applications.html#CICFlowMeter
2. https://github.com/ahlashkari/CICFlowMeter
