import csv
from abc import ABC


class OutputWriter(ABC):
    def __init__(self, output_file) -> None:
        self.file = open(output_file, "w")

    def write(self, data: dict) -> None:
        raise NotImplementedError

    def __del__(self):
        self.file.close()


class CSVWriter(OutputWriter):
    def __init__(self, output_file) -> None:
        super().__init__(output_file)

        self.line = 0
        self.writer = csv.writer(self.file)

    def write(self, data: dict) -> None:
        if self.line == 0:
            self.writer.writerow(data.keys())

        self.writer.writerow(data.values())
        self.line += 1


def output_writer_factory(output_mode, output_file) -> OutputWriter:
    if output_mode == "csv":
        return CSVWriter(output_file)
