#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import shutil
import re


lua51_builtins = (
    "_G", "_VERSION", "LUA_PATH", "assert", "collectgarbage", "coroutine",
    "debug", "dofile", "error", "gcinfo", "getfenv", "getmetatable", "io",
    "ipairs", "load", "loadfile", "loadstring", "math", "module",
    "newproxy", "next", "os", "package", "pairs", "pcall", "print",
    "rawequal", "rawget", "rawset", "require", "select", "setfenv",
    "setmetatable", "string", "table", "tonumber", "tostring", "type",
    "unpack", "xpcall",
)


cc_builtins = (
    "colors", "colours", "disk", "fs", "gps", "help", "io", "keys",
    "paintutils", "parallel", "peripheral", "rednet", "redstone", "shell",
    "term", "textutils", "turtle", "vector",
)


LUAC = None


def find_luac():
    global LUAC

    LUAC = os.environ.get("LUAC51")

    if LUAC:
        return os.access(LUAC, os.X_OK)

    if os.name == "nt":
        cclint_dir = os.path.dirname(os.path.abspath(__file__))
        LUAC = os.path.join(cclint_dir, "luac5.1.exe")

        if os.access(LUAC, os.X_OK):
            return True

    LUAC = shutil.which("luac5.1")

    return os.access(LUAC, os.X_OK)


def get_bytecode_listing(source):
    proc = subprocess.Popen(
        (LUAC, "-p", "-l", "-"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(source)

    return stdout.decode("ascii"), stderr.decode("ascii")


instruction_regex = re.compile(r"^\t\d+\t\[(?P<line>\d+)\]\t(?P<name>[A-Z]+)"
                               r"[ \t]+[\d -]*(\t; (?P<info>.*))?$")


def parse_bytecode(listing):
    instructions = []
    chunk = None

    for line in listing.split("\n"):
        line = line.rstrip("\r")

        if line.startswith("main <"):
            chunk = "main"
            continue

        if line.startswith("function <"):
            chunk = "function"
            continue

        match = instruction_regex.match(line)

        if match:
            instructions.append((
                chunk,
                int(match.group("line")),
                match.group("name"),
                match.group("info"),
            ))

    return instructions


def get_apis(instructions):
    apis = []
    i = 0
    n = len(instructions)

    while i < n:
        _, _, name, info = instructions[i]

        if name == "GETGLOBAL" and info in ("os", "bapil"):
            _, _, name, info = instructions[i+1]

            if name == "GETTABLE" and info == '"loadAPI"':
                _, _, name, info = instructions[i+2]

                if name == "LOADK":
                    _, _, name, _ = instructions[i+3]

                    if name == "CALL":
                        match = re.match(r"^\".*?(?P<api>[^/]+)\"$", info)

                        if match:
                            apis.append(match.group("api"))
                            i += 3

        i += 1

    return apis


def get_global_refs(instructions):
    refs = []

    for chunk, line, name, info in instructions:
        if name == "GETGLOBAL":
            refs.append(("get", line, info, chunk))

        elif name == "SETGLOBAL":
            refs.append(("set", line, info, chunk))

    return refs


def get_directives(source):
    ignore_global_get = []
    ignore_global_set = []

    for match in re.finditer(br"lint-ignore-global: (\w+(?:,\s*\w+)*)", source):
        for name in match.group(1).split(b","):
            name = name.decode("ascii").strip()
            ignore_global_get.append(name)
            ignore_global_set.append(name)

    for match in re.finditer(br"lint-ignore-global-get: (\w+(?:,\s*\w+)*)", source):
        for name in match.group(1).split(b","):
            name = name.decode("ascii").strip()
            ignore_global_get.append(name)

    for match in re.finditer(br"lint-ignore-global-set: (\w+(?:,\s*\w+)*)", source):
        for name in match.group(1).split(b","):
            name = name.decode("ascii").strip()
            ignore_global_set.append(name)

    set_globals_in_main = False

    if b"lint-set-globals-in-main-chunk" in source:
        set_globals_in_main = True

    cache_globals = False

    if b"lint-check-globals-cached" in source:
        cache_globals = True

    return ignore_global_get, ignore_global_set, set_globals_in_main, cache_globals


def check(source):
    line_mask = "{{:{}d}}".format(len(str(source.count(b"\n"))))
    messages = []

    def add_message(type_, line, message, *args):
        messages.append("{}:{}: {}".format(
            type_,
            line_mask.format(int(line)),
            message.format(*args) if args else message,
        ))

    listing, errors = get_bytecode_listing(source)

    if errors:
        for error in errors.split("\n"):
            match = re.match(r"^.+?:.+?:(?P<line>\d+): (?P<message>.+)$",
                             error.rstrip("\r"))

            if match:
                add_message("E", match.group("line"), match.group("message"))

        return messages

    instructions = parse_bytecode(listing)
    apis = get_apis(instructions)
    global_refs = get_global_refs(instructions)

    declared_globals = []

    for lst in (lua51_builtins, cc_builtins, apis):
        declared_globals.extend(lst)

    ignore_global_get, ignore_global_set, set_globals_in_main, cache_globals \
        = get_directives(source)

    if set_globals_in_main:
        for action, line, name, chunk in global_refs:
            if action != "set" or chunk != "main":
                continue

            ignore_global_get.append(name)
            ignore_global_set.append(name)

    warnings = []

    for action, line, name, chunk in global_refs:
        if action == "get":
            if name in ignore_global_get:
                continue

            if name in declared_globals:
                if not cache_globals:
                    continue

                if chunk == "main":
                    continue

        elif action == "set":
            if name == "_":
                continue

            if name in ignore_global_set:
                continue

        warnings.append((line, action, name))

    warnings.sort()

    for line, action, name in warnings:
        add_message("W", line, "global {} of '{}'", action, name)

    return messages


def main(argv=sys.argv):
    if not find_luac():
        print("error: luac5.1 not found")
        return 1

    if len(argv) < 2 or argv[1] == "-":
        source = sys.stdin.buffer.read()
    else:
        source = open(argv[1], "rb").read()

    for message in check(source):
        print(message)

    return 0


if __name__ == "__main__":
    sys.exit(main())
