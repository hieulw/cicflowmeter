import csv
from typing import Protocol

import requests


class OutputWriter(Protocol):
    def write(self, data: dict) -> None:
        raise NotImplementedError


class CSVWriter(OutputWriter):
    def __init__(self, output_file) -> None:
        self.output_file = output_file
        self.file = None
        self.writer = None
        self.line = 0
        self.rows = []
        self.fieldnames = None

    def write(self, data: dict) -> None:
        # Store the fieldnames from the first row
        if self.fieldnames is None:
            self.fieldnames = list(data.keys())
        
        # Buffer the row
        self.rows.append(data)
        self.line += 1

    def _flush_sorted(self):
        """Write all buffered rows sorted by first 4 columns"""
        if not self.rows:
            return
        
        # Sort rows by first 4 columns
        sort_keys = self.fieldnames[:4] if len(self.fieldnames) >= 4 else self.fieldnames
        
        self.rows.sort(key=lambda x: tuple(
            str(x.get(key, "")) for key in sort_keys
        ))
        
        # Write to file
        self.file = open(self.output_file, "w", newline='')
        self.writer = csv.writer(self.file)
        
        # Write header
        self.writer.writerow(self.fieldnames)
        
        # Write sorted rows
        for row in self.rows:
            self.writer.writerow([row.get(key, "") for key in self.fieldnames])
        
        self.file.flush()

    def __del__(self):
        try:
            self._flush_sorted()
            if self.file:
                self.file.close()
        except Exception:
            pass


class HttpWriter(OutputWriter):
    def __init__(self, output_url) -> None:
        self.url = output_url
        self.session = requests.Session()

    def write(self, data):
        try:
            resp = self.session.post(self.url, json=data, timeout=5)
            resp.raise_for_status()  # raise if not 2xx
        except Exception:
            self.logger.exception("HTTPWriter failed posting flow")

    def __del__(self):
        self.session.close()


def output_writer_factory(output_mode, output) -> OutputWriter:
    match output_mode:
        case "url":
            return HttpWriter(output)
        case "csv":
            return CSVWriter(output)
        case _:
            raise RuntimeError("no output_mode provided")
