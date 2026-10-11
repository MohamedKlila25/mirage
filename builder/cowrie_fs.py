"""Edit Cowrie's filesystem pickle.

Format checked against Cowrie 3.1.1 (cowrie/shell/fs.py): every entry is a 10-field list
[name, type, uid, gid, size, mode, ctime, contents, target, realfile]; a directory's contents
is the list of its children. Cowrie loads the pickle once per process, so new paths need a
restart; with [honeypot] contents_path set, each session reads file contents from disk.
"""
from __future__ import annotations

import pickle
import time
from pathlib import Path

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2
DIR_MODE, FILE_MODE, PRIVATE_MODE = 0o40755, 0o100644, 0o100600
FINGERPRINTS = ("/.dockerenv", "/home/phil")             # Cowrie defaults an attacker can recognize

Node = list


def load(path: str | Path) -> Node:
    """Only for Cowrie's own pickle (honeynet/cowrie/base_fs.pickle): unpickling runs code."""
    with open(path, "rb") as f:
        return pickle.load(f)


def dump(tree: Node, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(tree, f)


def _parts(path: str) -> list[str]:
    return [p for p in path.split("/") if p]


def find(tree: Node, path: str) -> Node | None:
    node = tree
    for part in _parts(path):
        if node[A_TYPE] != T_DIR:
            return None
        node = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
        if node is None:
            return None
    return node


def remove(tree: Node, path: str) -> bool:
    parent = find(tree, "/".join(_parts(path)[:-1]))
    if parent is None or parent[A_TYPE] != T_DIR:
        return False
    before = len(parent[A_CONTENTS])
    parent[A_CONTENTS][:] = [c for c in parent[A_CONTENTS] if c[A_NAME] != _parts(path)[-1]]
    return len(parent[A_CONTENTS]) < before


def mkdirs(tree: Node, path: str, uid: int = 0, gid: int = 0) -> Node:
    node = tree
    for part in _parts(path):
        child = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
        if child is None:
            child = [part, T_DIR, uid, gid, 4096, DIR_MODE, time.time(), [], None, None]
            node[A_CONTENTS].append(child)
        elif child[A_TYPE] != T_DIR:
            raise ValueError(f"{path}: {part} exists and is not a directory")
        node = child
    return node


def put_file(tree: Node, path: str, size: int, uid: int = 0, gid: int = 0, mode: int = FILE_MODE) -> Node:
    """Create or replace a regular file entry. Its contents come from contents_path on disk."""
    parts = _parts(path)
    parent = mkdirs(tree, "/" + "/".join(parts[:-1]))
    parent[A_CONTENTS][:] = [c for c in parent[A_CONTENTS] if c[A_NAME] != parts[-1]]
    node = [parts[-1], T_FILE, uid, gid, size, mode, time.time(), None, None, None]
    parent[A_CONTENTS].append(node)
    return node


def read_bytes(tree: Node, path: str) -> bytes | None:
    node = find(tree, path)
    if node is None or node[A_TYPE] != T_FILE or not isinstance(node[A_CONTENTS], bytes):
        return None
    return node[A_CONTENTS]
