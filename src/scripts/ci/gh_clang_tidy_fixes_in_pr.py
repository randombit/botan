#!/usr/bin/env python3

"""
(C) 2023 Jack Lloyd
    2023 René Meusel - Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import glob
import os
import sys

import yaml

class FileLocation:
    def __init__(self, line : int, column : int, endline : int | None = None, endcolumn : int | None = None):
        self.line = line
        self.column = column
        self.endline = endline
        self.endcolumn = endcolumn

    def has_range(self):
        return self.endline is not None and self.endcolumn is not None


class Diagnostic:
    @staticmethod
    def read_diagnostics_from(yaml_file : str):
        with open(yaml_file, encoding="utf-8") as yml:
            fixes = yaml.load(yml, Loader=yaml.FullLoader)
            if "Diagnostics" not in fixes:
                raise RuntimeError(f"No Diagnostics found in {yaml_file}")
            return [Diagnostic(diag) for diag in fixes["Diagnostics"]]


    def __map_file_path(self, file_path, base_path): # pylint: disable=unused-argument
        if file_path.endswith(".h"):
            raise RuntimeError(f"Header file {file_path} cannot be handled")
        # TODO: try to map include files (residing in build/include) onto their
        #       origin path in src/lib etc.
        return file_path


    def __map_file_offset(self, offset : int) -> tuple[int, int]:
        """ For self.file determine the (line, column) given a byte offset """
        with open(self.file, encoding="utf-8") as srcfile:
            readoffset = 0
            lineoffset = 0
            for l in srcfile.readlines():
                readoffset += len(l)
                lineoffset += 1
                if readoffset >= offset:
                    coloffset = offset - readoffset + len(l)
                    return (lineoffset, coloffset)
        raise RuntimeError(f"FileOffset {offset} out of range for {self.file}")


    def __map_file_location(self, msg):
        """ For self.file determine the specified error range of the message """
        location = self.__map_file_offset(msg["FileOffset"])
        if "Ranges" in msg and len(msg["Ranges"]) == 1:
            the_range = msg ["Ranges"][0]
            if the_range["FilePath"] == msg["FilePath"] and the_range["FileOffset"] == msg["FileOffset"]:
                endlocation = self.__map_file_offset(the_range["FileOffset"] + the_range["Length"])
                return FileLocation(*location, *endlocation)
        return FileLocation(*location)


    def __init__(self, yaml_diag):
        self.name = yaml_diag["DiagnosticName"]
        msg = yaml_diag["DiagnosticMessage"]
        self.message = msg["Message"]
        self.file = self.__map_file_path(msg["FilePath"], yaml_diag["BuildDirectory"])
        self.level = yaml_diag["Level"]
        self.location = self.__map_file_location(msg)


def render_as_github_annotations(diagnostics : list[Diagnostic]):
    def map_level(level : str) -> str:
        if level == "Error":
            return "error"
        elif level == "Warning":
            return "warning"
        else:
            return "notice" # fallback: likely never used

    def render_location(location : FileLocation) -> str:
        linemarkers = [f"line={location.line}"]
        colmarkers = [f"col={location.column}"]
        if location.has_range():
            linemarkers += [f"endLine={location.endline}"]
            colmarkers += [f"endColumn={location.endcolumn}"]
        return ','.join(linemarkers + colmarkers)

    def render_message(msg: str) -> str:
        return msg.replace("\n", " - ")

    for d in diagnostics:
        lvl = map_level(d.level)
        location = render_location(d.location)
        msg = render_message(d.message)
        print(f"::{lvl} file={d.file},{location}::{msg}")


def main():
    parser = argparse.ArgumentParser(prog="ClangTidy Decoder",
                                     description="Parses ClangTidy YAML output and emits GitHub Workflow commands")
    parser.add_argument('directory')
    args = parser.parse_args()

    diagnostics = []
    for yml in glob.glob(os.path.join(args.directory, "*.yml")):
        diagnostics.extend(Diagnostic.read_diagnostics_from(yml))

    render_as_github_annotations(diagnostics)

if __name__ == '__main__':
    sys.exit(main())
