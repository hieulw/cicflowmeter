# Python CICFlowMeter

> This project is not maintained actively by me. If you found something wrong (bugs, incorrect results) feel free to create issues or pull requests.

---

## ⚡️ Version 0.4.0: Major Refactor (June 2025)

- The tool now uses a custom `FlowSession` and the `prn` callback of Scapy's `AsyncSniffer` for all flow processing, instead of relying on Scapy's `DefaultSession`/session system.
- All flow logic, feature extraction, and output are now fully managed by the project code, not by Scapy internals.
- The `process` method always returns `None`, preventing unwanted packet printing by Scapy.
- Logging is robust: only shows debug output if `-v` is set.
- All flows are always flushed at the end, even for small pcaps.
- This project is a CICFlowMeter-like tool (see [UNB CICFlowMeter](https://www.unb.ca/cic/research/applications.html#CICFlowMeter)), not Cisco NetFlow. It extracts custom flow features as in the original Java CICFlowMeter.
- The refactor does not change the set of features/fields extracted, only how packets are routed to your logic.

---

### Installation

```sh
git clone https://github.com/hieulw/cicflowmeter
cd cicflowmeter
uv sync
source .venv/bin/activate
```

### Usage

```sh
usage: cicflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE | -d INPUT_DIRECTORY) (-c | -u) [--fields FIELDS] [--merge] [-v] output

positional arguments:
  output                output file name (in csv mode), url (in url mode), or output directory (in directory mode)

options:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE, --interface INPUT_INTERFACE
                        capture online data from INPUT_INTERFACE
  -f INPUT_FILE, --file INPUT_FILE
                        capture offline data from INPUT_FILE
  -d INPUT_DIRECTORY, --directory INPUT_DIRECTORY
                        capture offline data from all pcap files in INPUT_DIRECTORY
  -c, --csv             output flows as csv
  -u, --url             output flows as request to url
  --fields FIELDS       comma separated fields to include in output (default: all)
  --merge               merge all pcap files into a single CSV (only works with -d/--directory mode)
  -v, --verbose         more verbose
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

Convert all PCAP files in a directory (separate CSVs)

```
cicflowmeter -d ./pcap_folder/ -c ./csv_output/
```

Convert all PCAP files in a directory (merged into single CSV)

```
cicflowmeter -d ./pcap_folder/ -c ./csv_output/ --merge
```

Sniff packets real-time from interface to flow request: (**need root permission**)

```
cicflowmeter -i eth0 -u http://localhost:8080/predict
```

### References:

1. https://www.unb.ca/cic/research/applications.html#CICFlowMeter
2. https://github.com/ahlashkari/CICFlowMeter
