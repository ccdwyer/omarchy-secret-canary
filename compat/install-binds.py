#!/usr/bin/env python3
"""Append, replace, or remove a marked o.bind block in ~/.config/hypr/bindings.lua.

Never unbinds other plugins or user shortcuts. Only this plugin's
`-- BEGIN <id>` / `-- END <id>` block is touched.
"""

import os
import sys


def usage() -> None:
    print(
        "usage: install-binds.py PLUGIN_ID LUA_BLOCK\n"
        "       install-binds.py --remove PLUGIN_ID",
        file=sys.stderr,
    )


def bindings_path() -> str:
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(config_home, "hypr", "bindings.lua")


def read_text(path: str) -> str:
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    return ""


def write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def strip_block(text: str, begin: str, end: str) -> str:
    if begin not in text or end not in text:
        return text
    pre = text[: text.index(begin)]
    post = text[text.index(end) + len(end) :].lstrip("\n")
    text = pre.rstrip()
    if post:
        text = text + "\n\n" + post.lstrip()
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def upsert_block(text: str, begin: str, end: str, chunk: str) -> str:
    if begin in text and end in text:
        pre = text[: text.index(begin)]
        post = text[text.index(end) + len(end) :].lstrip("\n")
        text = pre.rstrip() + "\n\n" + chunk
        if post:
            text = text.rstrip() + "\n" + post
            if not text.endswith("\n"):
                text += "\n"
        return text
    if text and not text.endswith("\n"):
        text += "\n"
    text = text.rstrip() + "\n\n" + chunk
    if not text.endswith("\n"):
        text += "\n"
    return text


def main() -> int:
    args = sys.argv[1:]
    if not args:
        usage()
        return 2
    remove = False
    plugin_id = ""
    block = ""
    if args[0] == "--remove":
        if len(args) != 2:
            usage()
            return 2
        remove = True
        plugin_id = args[1]
    else:
        if len(args) != 2:
            usage()
            return 2
        plugin_id = args[0]
        block = args[1]
    if not plugin_id or "\n" in plugin_id or plugin_id.startswith("-"):
        usage()
        return 2
    path = bindings_path()
    begin = f"-- BEGIN {plugin_id}"
    end = f"-- END {plugin_id}"
    text = read_text(path)
    if remove:
        write_text(path, strip_block(text, begin, end))
        print("ok")
        return 0
    if not block.endswith("\n"):
        block += "\n"
    chunk = f"{begin}\n{block}{end}\n"
    write_text(path, upsert_block(text, begin, end, chunk))
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
