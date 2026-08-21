#!/usr/bin/env python3
"""Append, replace, or remove a marked o.bind block in ~/.config/hypr/bindings.lua.

Never unbinds other plugins or user shortcuts. Only this plugin's
`-- BEGIN <id>` / `-- END <id>` block is touched.
"""

import os
import stat
import tempfile
import sys



def _refuse_symlink(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise OSError("refusing symlink: %s" % path)
    if not stat.S_ISREG(st.st_mode):
        raise OSError("not a regular file: %s" % path)


def read_text_nofollow(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        data = os.read(fd, 4_000_000)
    finally:
        os.close(fd)
    return data.decode("utf-8")


def write_text_atomic(path: str, text: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    pst = os.lstat(parent)
    if stat.S_ISLNK(pst.st_mode):
        raise OSError("refusing symlink directory: %s" % parent)
    _refuse_symlink(path)
    fd, tmp = tempfile.mkstemp(prefix=".bindings.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise OSError("refusing to leave a symlink at %s" % path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
    if os.path.islink(path):
        raise OSError("refusing symlink: %s" % path)
    if os.path.isfile(path):
        return read_text_nofollow(path)
    return ""


def write_text(path: str, text: str) -> None:
    write_text_atomic(path, text)


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
    try:
        text = read_text(path)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
