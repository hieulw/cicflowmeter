# Python CICFlowMeter

> This project is not maintained actively by me. If you found something wrong (bugs, incorrect results) feel free to create issues or pull requests.

### Installation

```sh
git clone https://github.com/hieulw/cicflowmeter
cd cicflowmeter
uv sync
source .venv/bin/activate
```

### Usage

```sh
usage: cicflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) (-c | -u) [--fields FIELDS] [-v] output

positional arguments:
  output                output file name (in csv mode) or url (in url mode)

options:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE, --interface INPUT_INTERFACE
                        capture online data from INPUT_INTERFACE
  -f INPUT_FILE, --file INPUT_FILE
                        capture offline data from INPUT_FILE
  -c, --csv             output flows as csv
  -u, --url             output flows as request to url
  --fields FIELDS       comma separated fields to include in output (default: all)
  -v, --verbose         more verbose
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow request: (**need root permission**)

```
cicflowmeter -i eth0 -u http://localhost:8080/predict
```

### References:

1. https://www.unb.ca/cic/research/applications.html#CICFlowMeter
2. https://github.com/ahlashkari/CICFlowMeter
