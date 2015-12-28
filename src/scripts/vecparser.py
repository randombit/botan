from collections import OrderedDict
import re

class VecDocument:
    def __init__(self, filepath):
        self.data = OrderedDict()
        last_testcase_number = 1
        current_testcase_number = 1
        current_group_name = ""
        last_group_name = ""
        current_testcase = {}

        PATTERN_GROUPHEADER = "^\[(.+)\]$"
        PATTERN_KEYVALUE = "^\s*([a-zA-Z]+)\s*=(.*)$"

        with open(filepath, 'r') as f:
            # Append one empty line to simplify parsing
            lines = f.read().splitlines() + ["\n"]

            for line in lines:
                line = line.strip()
                if line.startswith("#"):
                    pass # Skip
                elif line == "":
                    current_testcase_number += 1
                elif re.match(PATTERN_GROUPHEADER, line):
                    match = re.match(PATTERN_GROUPHEADER, line)
                    current_group_name = match.group(1)
                elif re.match(PATTERN_KEYVALUE, line):
                    match = re.match(PATTERN_KEYVALUE, line)
                    key = match.group(1)
                    value = match.group(2).strip()
                    current_testcase[key] = value

                if current_testcase_number != last_testcase_number:
                    if not current_group_name in self.data:
                        self.data[current_group_name] = []
                    if len(current_testcase) != 0:
                        self.data[current_group_name].append(current_testcase)
                    current_testcase = {}
                    last_testcase_number = current_testcase_number

                if current_group_name != last_group_name:
                    last_group_name = current_group_name
                    # Reset testcase number
                    last_testcase_number = 1
                    current_testcase_number = 1

    def get_data(self):
        return self.data
