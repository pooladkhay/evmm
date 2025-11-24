#!/usr/bin/python3

import json
import re

with open("compile_commands.json") as f:
    data = json.load(f)

remove_flags = [
    r"-fno-allow-store-data-races",
    r"-fzero-init-padding-bits=all",
    r"-fconserve-stack",
    r"-fmin-function-alignment=16",
    r"-mindirect-branch-register",
    r"-mindirect-branch=thunk-extern",
    r"-mpreferred-stack-boundary=3",
    r"-mrecord-mcount",
    r"-fsanitize=bounds-strict",
]

pattern = re.compile("|".join(remove_flags))

for entry in data:
    args = entry["arguments"] if "arguments" in entry else entry["command"].split()
    filtered = [arg for arg in args if not pattern.search(arg)]
    if "arguments" in entry:
        entry["arguments"] = filtered
    else:
        entry["command"] = " ".join(filtered)

with open("compile_commands.json", "w") as f:
    json.dump(data, f, indent=2)
