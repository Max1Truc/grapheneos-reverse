import gzip
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import zipfile

IGNORED_FILES = {"avb_pkmd.bin"}
BINARY_FILES = [
    re.compile(pattern)
    for pattern in [
        "apex_pubkey",
        r"waves_preset\.mps",
        r"hyph-.*\.hyb",
        "publicsuffixes",
        "stamp-cert-sha256",
        "tzdata",
        r"RFF.*\.bmd",
        "eccdata",
        r".*\.gatf",
        r"libclcore.*\.bc",
        r"u-boot\.bin",
        "base",
        "mode_[26]_ch",
        "mode_xaural",
        r".*\.bin",
        "unindexed_ruleset[a-z_]*",
        r".*\.RSA",
        "[a-z_]*sepolicy",
        r".*\.[vo]dex",
        r".*\.mid",
        r".*\.art",
        r".*.fsv_meta",
        r".*.idsig",
        r".*\.bcmap",
        r".*vbmeta.img",
        r".*\.bfbs",
        r".*\.bin\+app\.vanadium\.webview\+",
        r".*\.binarypb",
        r".*\.dat",
        r".*\.dat\+app\.vanadium\.webview\+",
        r".*\.der",
        r".*\.exr",
        r".*\.icc",
        r".*\.jpg",
        r".*\.kotlin_builtins",
        r".*\.kotlin_module",
        r".*\.map",
        r".*\.mp4",
        r".*\.ogg",
        r".*\.pak",
        r".*\.pak\+app\.vanadium\.webview\+",
        r".*\.pb",
        r".*\.pfb",
        r".*\.png",
        r".*\.b?profm?",
        r".*\.res",
        r".*\.ttf",
        r".*\.otf",
        r".*\.ttc",
        r".*\.wav",
        r".*_heterodyne_info",
        r"CERT\.SF",
        r"DebugProbesKt\.bin",
        r"MANIFEST\.MF",
        r"PhoneNumberAlternateFormatsProto_.*",
        r"PhoneNumberMetadataProto_.*",
        r"ShortNumberMetadataProto_.*",
        r"[a-z_.]+\.model",
        r"bootloader-.*\.img",
        r"d3m2.ec.bin",
        r"deflate_dictionary_[0-9]+\.bin",
        r"empty\.dict",
        r"evt\.ec\.bin",
        r"flag\.info",
        r"flag\.val",
        r"main\.dict",
        r"main_[a-z]{2}\.dict",
        r"main_[a-z]{2}_[a-z]{2}\.dict",
        r".*\.tflite",
        r"proto11\.ec\.bin",
        r"proto_config\.pb2",
        r"pvmfw\.img",
        r"radio-.*\.img",
    ]
]

con = sqlite3.connect("reverse_state.sqlite3")
cur = con.cursor()

cur.executescript("""
-- https://briandouglas.ie/sqlite-defaults/
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA cache_size = -20000;
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 2147483648;
PRAGMA page_size = 8192;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS files (path TEXT NOT NULL UNIQUE, status TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS "files_todo" ON "files" ("path" ASC) WHERE status = 'TODO';
""")


def add_paths(paths):
    str_paths = list(map(str, paths))
    cur.executemany(
        "INSERT INTO files(path, status) VALUES(?, 'TODO')",
        [(path,) for path in str_paths],
    )
    con.commit()
    for path in str_paths:
        print("TODO", path)


def set_paths_status(elements):
    cur.executemany("UPDATE files SET status = ? WHERE path = ?", list(elements))
    con.commit()
    for status, path in elements:
        print(status, path)


def process(path):
    path = pathlib.Path(path)

    if not path.exists(follow_symlinks=False):
        return False

    extract_path = path.with_suffix(".d")
    size = path.stat(follow_symlinks=False).st_size

    if path.is_symlink():
        return True
    if str(path).endswith("/super.d/vendor_a.d/firmware"):
        # skip unpacking firmwares
        return True
    if path.is_dir():
        add_paths(path.iterdir())
        return True
    if path.name in IGNORED_FILES:
        return True
    for pattern in BINARY_FILES:
        if pattern.fullmatch(path.name):
            return True
    if size == 0:
        # empty file
        return True

    magic = path.open("rb").read(4)

    if path.name == "microdroid_super.img":
        output_path = path.with_name("microdroid_super.img.simg2img")
        add_paths([output_path])
        proc = subprocess.Popen(
            ["simg2img", path, output_path],
        )
        proc.communicate()
        assert proc.returncode == 0
        return True
    if re.fullmatch(r"super_[0-9]+\.img", path.name):
        supers_list = [
            str(child)
            for child in path.parent.iterdir()
            if re.fullmatch(r"super_[0-9]+\.img", child.name)
        ]
        output_path = path.with_name("super.img")
        add_paths([output_path])
        proc = subprocess.Popen(
            ["simg2img", *supers_list, output_path],
        )
        proc.communicate()
        assert proc.returncode == 0
        set_paths_status([("OK", p) for p in supers_list])
        return True
    if path.name[-3:] == ".gz":
        output_path = path.with_name(path.name[:-3])
        add_paths([output_path])
        with output_path.open("wb") as f_out:
            with gzip.open(path, "rb") as f_in:
                shutil.copyfileobj(f_in, f_out)
        return True
    if path.suffix in (".apk", ".apex", ".jar"):
        # webassembly
        add_paths([extract_path])
        proc = subprocess.Popen(
            ["jadx", "-j", "1", "--show-bad-code", "-d", extract_path, path],
            stdout=subprocess.PIPE,
        )
        proc.communicate()
        return True
    if path.suffix == ".zip" or magic == b"PK\x03\x04":
        os.mkdir(extract_path)
        add_paths([extract_path])
        archive = zipfile.ZipFile(path)
        names = archive.namelist()
        inside_zip_prefixes = [path.split("/")[0] for path in names]
        all_files_have_same_prefix = all(
            prefix == inside_zip_prefixes[0] for prefix in inside_zip_prefixes
        )
        only_one_depth = all(
            len(parts) == 2 and len(parts[1]) > 0
            for parts in filter(lambda x: x.split("/"), names)
        )
        if all_files_have_same_prefix and only_one_depth:
            for name in names:
                name_without_prefix = "/".join(name.split("/")[1:])
                (extract_path / name_without_prefix).write_bytes(archive.read(name))
        else:
            archive.extractall(extract_path, names)
        return True
    if path.name in (
        "boot.img",
        "init_boot.img",
        "vendor_boot.img",
        "vendor_kernel_boot.img",
    ):
        proc = subprocess.Popen(
            ["unpack_bootimg", "--boot_img", str(path), "--out", str(extract_path)],
            stdout=subprocess.PIPE,
        )
        outs, errs = proc.communicate()
        assert proc.returncode == 0
        add_paths([extract_path])
        return True
    if path.name == "super.img" or path.suffix == ".simg2img":
        add_paths([extract_path])
        proc = subprocess.Popen(
            [
                "lpunpack",
                str(path),
                str(extract_path),
            ],
            stdout=subprocess.PIPE,
        )
        outs, errs = proc.communicate()
        assert proc.returncode == 0
        return True
    if path.name == "dtbo.img":
        add_paths([extract_path])
        os.mkdir(extract_path)
        proc = subprocess.Popen(
            [
                "mkdtboimg",
                "dump",
                str(path),
                "-b",
                str(extract_path / "dtb"),
                "-o",
                str(extract_path / "dtbo.txt"),
            ],
            stdout=subprocess.PIPE,
        )
        outs, errs = proc.communicate()
        assert proc.returncode == 0
        return True
    if path.suffix == ".wasm":
        # webassembly
        wasm_data = path.read_bytes()

        proc = subprocess.Popen(
            ["wasm2wat", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        wat_data, _ = proc.communicate(wasm_data)

        output_file = path.with_suffix(".wat")
        assert proc.returncode == 0
        add_paths([output_file])
        output_file.write_bytes(wat_data)
        return True
    magic = path.open("rb").read(4)
    if magic == b"\x89PNG":
        # PNG format
        return True
    if magic == b"RIFF":
        # RIFF format
        return True
    if magic == b"\x02\x21\x4c\x18":
        # LZ4 legacy
        compressed_data = path.read_bytes()

        proc = subprocess.Popen(
            ["lz4", "-d"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        decompressed_data, _ = proc.communicate(compressed_data)

        output_file = path.with_suffix(path.suffix + ".unlz4")
        add_paths([output_file])
        output_file.write_bytes(decompressed_data)
        return True
    if magic == bytes.fromhex("d00dfeed"):
        # DTB files
        output_path = path.with_suffix(path.suffix + ".dts")
        proc = subprocess.Popen(
            ["dtc", "-s", "-q", "-I", "dtb", "-O", "dts"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        plaintext_data, _ = proc.communicate(path.read_bytes())
        assert proc.returncode == 0

        add_paths([output_path])
        output_path.write_bytes(plaintext_data)
        return True
    if magic == b"0707":
        # cpio archive (plaintext)
        add_paths([extract_path])
        os.mkdir(extract_path)
        proc = subprocess.Popen(["cpio", "-i", "-F", path.absolute()], cwd=extract_path)
        proc.communicate()
        return True
    if magic[:2] == bytes.fromhex("aced"):
        # Java serialization data
        # https://github.com/file/file/blob/bb955ca335d2f90ade1ed1ced239eb9ff8d9896d/magic/Magdir/java#L10
        return True
    if magic == b"\x7fELF":
        # ELF file
        return True

    # ext2/ext3/ext4 filesystems ?
    if size > 2000:
        f = path.open("rb")
        f.seek(0x438)
        magic = f.read(2)
        if magic == b"\x53\xef":
            add_paths([extract_path])
            os.mkdir(extract_path)
            assert " " not in str(
                extract_path
            ), "please no spacebar in extract path to avoid accidental injections"
            proc = subprocess.Popen(
                [
                    "debugfs",
                    "-R",
                    "rdump / " + str(extract_path),
                    str(path),
                ],
                stdout=subprocess.PIPE,
            )
            outs, errs = proc.communicate()
            assert proc.returncode == 0
            return True

        f.seek(0x38)
        magic = f.read(4)
        if magic == bytes.fromhex("41524d64"):
            # ARM64 kernel
            return True

        f.seek(0x1000)
        magic = f.read(4)
        if magic == b"\x7fELF":
            # weird ELF stuff like in super.d/vendor_a.d/etc/chre/activity.so
            # this may be worth looking into:
            #  https://source.android.com/docs/core/interaction/contexthub
            return True

    if size < 20_000_000:
        # if file is <10MB and is valid UTF-8
        # then assume it is a plaintext file
        # and accept it as it is
        content = path.read_bytes()
        try:
            content.decode("utf8", "strict")
            return True
        except:
            pass

        # also try Windows-1252 encoding
        try:
            content.decode("cp1252", "strict")
            return True
        except:
            pass

    return False


def process_all():
    while True:
        result = cur.execute(
            "SELECT path FROM files WHERE status = 'TODO' ORDER BY path LIMIT 1"
        ).fetchone()
        if result is None:
            print("DONE")
            break

        current_path = result[0]

        print("PROCESSING", current_path)
        result = process(current_path)
        if result:
            set_paths_status([("OK", current_path)])
        else:
            print("UNKNOWN", current_path)
            print("\nfile format information:", pathlib.Path(current_path).name)
            subprocess.Popen(["ls", "-lh", "--", current_path]).communicate()
            subprocess.Popen(["file", "--", current_path]).communicate()
            subprocess.Popen(["xxd", "-l", "128", "--", current_path]).communicate()
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print(" reverse.py add [file1 [file2 ...]]")
        print(" reverse.py del [file1 [file2 ...]]")
        print(" reverse.py list")
        print(" reverse.py process")
        exit(1)
    match sys.argv[1]:
        case "add":
            paths = sys.argv[2:]
            add_paths(paths)
        case "list":
            for path, status in cur.execute(
                "SELECT path, status FROM files ORDER BY path"
            ):
                print(status, path)
        case "process":
            process_all()
        case "del":
            paths = sys.argv[2:]
            cur.executemany(
                "DELETE FROM files WHERE path = ? OR path LIKE CONCAT(?, '/%')",
                [
                    (
                        path,
                        path,
                    )
                    for path in paths
                ],
            )
            con.commit()
        case _:
            print("invalid command", repr(sys.argv[1]))
            exit(1)
