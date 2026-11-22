from pathlib import Path
import gzip, os, stat, sys

root = Path(sys.argv[1])

with gzip.open(sys.argv[2], "wb", compresslevel=1) as archive:
    def entry(name, inode, mode, contents, size):
        fields = (inode, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name) + 1, 0)
        header = b"070701" + b"".join(f"{part:08x}".encode() for part in fields) + name + b"\0"
        archive.write(header + b"\0" * (-len(header) % 4))
        if contents:
            archive.write(contents)
        archive.write(b"\0" * (-size % 4))

    for inode, path in enumerate(sorted(root.rglob("*")), 1):
        if path.relative_to(root).parts[0] == "boot":
            continue
        mode = path.lstat().st_mode
        contents = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes() if stat.S_ISREG(mode) else b""
        entry(os.fsencode(path.relative_to(root)), inode, mode, contents, len(contents))
    entry(b"TRAILER!!!", 0, 0, b"", 0)
