from pathlib import Path
from subprocess import Popen, PIPE
from zipfile import ZipFile
import logging
import os
import re
import shutil
import sys
import zlib

logger = logging.getLogger(__name__)


def get_file_crc(f):
    current_crc = 0
    while chunk := f.read(1_000_000):
        current_crc = zlib.crc32(chunk, current_crc)
    return current_crc


def similar_zip(zipname1, zipname2):
    zip1 = ZipFile(zipname1)
    zip2 = ZipFile(zipname2)
    for file1, file2 in zip(zip1.infolist(), zip2.infolist(), strict=True):
        name = file1.filename
        if name != file2.filename:
            logger.debug(f"ZIP/WRONGFILENAME {zipname1} {zipname2} {name}")
            return False
        elif file1.CRC == file2.CRC:
            logger.debug(f"ZIP/CRCEQUAL {zipname1} {zipname2} {name}")
            continue
        elif name in (
            "META-INF/CERT.SF",
            "META-INF/CERT.RSA",
            "META-INF/MANIFEST.MF",
            "keys/releasekey.x509.pem",
            "apex_pubkey",
        ):
            logger.debug(f"ZIP/IGNORE {zipname1} {zipname2} {name}")
        else:
            logger.debug(f"ZIP/CRCDIFF {zipname1} {zipname2} {name}")
            return False
    return True


def extract_zip(zipname1, zipname2):
    extractdir1 = zipname1.with_suffix(".d")
    extractdir2 = zipname2.with_suffix(".d")
    if zipname1.suffix in (".apex", ".apk", ".jar"):
        proc1 = Popen(
            ["jadx", "-j", "1", "--show-bad-code", "-d", extractdir1, zipname1],
            stdout=PIPE,
        )
        proc2 = Popen(
            ["jadx", "-j", "1", "--show-bad-code", "-d", extractdir2, zipname2],
            stdout=PIPE,
        )
        proc1.communicate()
        proc2.communicate()
    else:
        ZipFile(zipname1).extractall(extractdir1)
        ZipFile(zipname2).extractall(extractdir2)
    logger.debug(f"EXTRACT {zipname1} {zipname2}")
    diff(extractdir1, extractdir2)


def diff(file1: Path | str, file2: Path | str):
    file1 = Path(file1)
    file2 = Path(file2)

    name = file1.name
    assert file2.name == name

    logger.debug(f"PROCESSING {file1} {file2}")

    extractdir1 = file1.with_suffix(".d")
    extractdir2 = file2.with_suffix(".d")

    if file1.is_symlink():
        assert file2.is_symlink()
        logger.debug(f"IGNORE {file1} {file2}")
        return
    if not file1.exists() or not file2.exists():
        logger.info(f"DIFF {file1} {file2}")
        return
    if file1.is_dir():
        assert file2.is_dir()
        filelist1 = set(file.name for file in file1.iterdir())
        filelist2 = set(file.name for file in file2.iterdir())
        filelist = sorted(filelist1.union(filelist2))
        logger.debug(f"DIR {file1} {file2}")
        for name in filelist:
            diff(file1 / name, file2 / name)
        return

    crc1 = get_file_crc(file1.open("rb"))
    crc2 = get_file_crc(file2.open("rb"))

    if crc1 == crc2:
        logger.debug(f"EQUAL {file1} {file2}")
        return
    if name in (
        "CERT.SF",
        "CERT.RSA",
        "MANIFEST.MF",
        "releasekey.x509.pem",
        "apex_pubkey",
        "microdroid_vbmeta.img",
        "vendor_mac_permissions.xml",
        "plat_mac_permissions.xml",
    ) or file1.suffix in (".png",):
        logger.debug(f"IGNORE {file1} {file2}")
        return
    if name == "microdroid_super.img":
        output1 = file1.with_name("microdroid_super.img.simg2img")
        output2 = file2.with_name("microdroid_super.img.simg2img")
        proc1 = Popen(["simg2img", file1, output1])
        proc2 = Popen(["simg2img", file2, output2])
        proc1.communicate()
        proc2.communicate()
        assert proc1.returncode == 0
        assert proc2.returncode == 0
        logger.debug(f"EXTRACT {file1} {file2}")
        diff(output1, output2)
        return
    if name[-3:] == ".gz":
        output1 = file1.with_name(name[:-3])
        output2 = file2.with_name(name[:-3])
        with output1.open("wb") as f_out:
            with gzip.open(file1, "rb") as f_in:
                shutil.copyfileobj(f_in, f_out)
        with output2.open("wb") as f_out:
            with gzip.open(file2, "rb") as f_in:
                shutil.copyfileobj(f_in, f_out)
        logger.debug(f"EXTRACT {file1} {file2}")
        diff(output1, output2)
        return
    if name in (
        "boot.img",
        "init_boot.img",
        "pvmfw.img",
        "vendor_boot.img",
        "vendor_kernel_boot.img",
    ):
        proc1 = Popen(
            ["unpack_bootimg", "--boot_img", str(file1), "--out", str(extractdir1)],
            stdout=PIPE,
        )
        proc2 = Popen(
            ["unpack_bootimg", "--boot_img", str(file2), "--out", str(extractdir2)],
            stdout=PIPE,
        )
        proc1.communicate()
        proc2.communicate()
        assert proc1.returncode == 0
        assert proc2.returncode == 0
        logger.debug(f"EXTRACT {file1} {file2}")
        diff(extractdir1, extractdir2)
        return
    if name in ("super.img", "microdroid_super.img.simg2img"):
        proc1 = Popen(["lpunpack", file1, extractdir1], stdout=PIPE)
        proc2 = Popen(["lpunpack", file2, extractdir2], stdout=PIPE)
        proc1.communicate()
        proc2.communicate()
        assert proc1.returncode == 0
        assert proc2.returncode == 0
        logger.debug(f"EXTRACT {file1} {file2}")
        diff(extractdir1, extractdir2)
        return

    magic = file1.open("rb").read(4)
    if magic == b"PK\x03\x04":
        # zip, jar, apk
        if similar_zip(file1, file2):
            logger.debug(f"SIMILAR {file1} {file2}")
            return
        if name.endswith(".apex"):
            # .apex files may contain
            # embedded EXT2 filesystems
            # "apex_payload.img"
            logger.debug(f"EXTRACT {file1} {file2}")
        else:
            logger.info(f"DIFF {file1} {file2}")
        extract_zip(file1, file2)
        return
    if magic == b"\x02\x21\x4c\x18":
        # LZ4 legacy
        compresseddata1 = file1.read_bytes()
        proc1 = Popen(
            ["lz4", "-d"],
            stdin=PIPE,
            stdout=PIPE,
        )
        decompresseddata1, _ = proc1.communicate(compresseddata1)
        output1 = file1.with_suffix(file1.suffix + ".unlz4")
        output1.write_bytes(decompresseddata1)

        compresseddata2 = file2.read_bytes()
        proc2 = Popen(
            ["lz4", "-d"],
            stdin=PIPE,
            stdout=PIPE,
        )
        decompresseddata2, _ = proc2.communicate(compresseddata2)
        output2 = file2.with_suffix(file2.suffix + ".unlz4")
        output2.write_bytes(decompresseddata2)

        logger.debug(f"EXTRACT {file1} {file2}")
        diff(output1, output2)
        return
    if magic == bytes.fromhex("d00dfeed"):
        # DTB files
        output1 = file1.with_suffix(file1.suffix + ".dts")
        proc1 = Popen(
            ["dtc", "-s", "-q", "-I", "dtb", "-O", "dts"],
            stdin=PIPE,
            stdout=PIPE,
        )
        plaintext1, _ = proc1.communicate(file1.read_bytes())
        assert proc1.returncode == 0
        output1.write_bytes(plaintext1)

        output2 = file2.with_suffix(file2.suffix + ".dts")
        proc2 = Popen(
            ["dtc", "-s", "-q", "-I", "dtb", "-O", "dts"],
            stdin=PIPE,
            stdout=PIPE,
        )
        plaintext2, _ = proc2.communicate(file2.read_bytes())
        assert proc2.returncode == 0
        output2.write_bytes(plaintext2)

        logger.debug(f"EXTRACT {file1} {file2}")
        diff(output1, output2)
        return
    if magic == b"0707":
        # cpio archive (plaintext)
        os.makedirs(extractdir1, exist_ok=True)
        os.makedirs(extractdir2, exist_ok=True)
        proc1 = Popen(
            ["cpio", "-i", "-F", file1.absolute()], cwd=extractdir1
        ).communicate()
        proc2 = Popen(
            ["cpio", "-i", "-F", file2.absolute()], cwd=extractdir2
        ).communicate()

        logger.debug(f"EXTRACT {file1} {file2}")
        diff(extractdir1, extractdir2)
        return True

    f = file1.open("rb")
    f.seek(0x438)
    magic = f.read(2)
    if magic == b"\x53\xef":
        os.makedirs(extractdir1, exist_ok=True)
        os.makedirs(extractdir2, exist_ok=True)
        proc1 = Popen(
            [
                "debugfs",
                "-R",
                "rdump / " + str(extractdir1),
                file1,
            ],
            stdout=PIPE,
            stderr=PIPE,
        )
        proc2 = Popen(
            [
                "debugfs",
                "-R",
                "rdump / " + str(extractdir2),
                file2,
            ],
            stdout=PIPE,
            stderr=PIPE,
        )
        proc1.communicate()
        proc2.communicate()
        assert proc1.returncode == 0
        assert proc2.returncode == 0
        logger.debug(f"EXTRACT {file1} {file2}")
        diff(extractdir1, extractdir2)
        return

    logger.info(f"DIFF {file1} {file2}")


def extract_zip_member(zf: ZipFile, member_name: str, destination_name: str):
    try:
        f = open(destination_name, "rb")
    except FileNotFoundError:
        shutil.copyfileobj(zf.open(member_name), open(destination_name, "wb"))
    else:
        target_crc = zf.getinfo(member_name).CRC
        assert get_file_crc(f) == target_crc


def merge_super_files(dirname, filenames):
    Popen(
        [
            "simg2img",
            *[dirname / filename for filename in filenames],
            dirname / "super.img",
        ]
    ).communicate()


def diff_release_zips(filename1: str, filename2: str):
    filename1 = Path(filename1)
    filename2 = Path(filename2)

    zip1 = ZipFile(filename1)
    zip2 = ZipFile(filename2)

    extractdir1 = filename1.with_suffix(".d")
    extractdir2 = filename2.with_suffix(".d")
    os.makedirs(extractdir1, exist_ok=True)
    os.makedirs(extractdir2, exist_ok=True)

    super_filenames = []

    for file1, file2 in zip(zip1.infolist(), zip2.infolist(), strict=True):
        name = file1.filename.split("/", maxsplit=1)[1]
        assert name == file2.filename.split("/", maxsplit=1)[1]

        assert not file1.is_dir()
        assert not file2.is_dir()

        if re.fullmatch(r"super_[0-9]+\.img", name):
            logger.debug("RELEASEZIP/EXTRACT " + name)
            extract_zip_member(zip1, file1.filename, extractdir1 / name)
            extract_zip_member(zip2, file2.filename, extractdir2 / name)
            super_filenames.append(name)
            continue

        # it's not a cryptographic hash
        # TODO hash the file ourselves
        if file1.CRC == file2.CRC:
            logger.debug("RELEASEZIP/EQUAL " + name)
            continue

        if name in ("avb_pkmd.bin", "vbmeta.img"):
            logger.debug("RELEASEZIP/IGNORE " + name)
            continue

        extract_zip_member(zip1, file1.filename, extractdir1 / name)
        extract_zip_member(zip2, file2.filename, extractdir2 / name)
        diff(extractdir1 / name, extractdir2 / name)

    logger.debug("RELEASEZIP/MERGE_SUPER_FILES")
    merge_super_files(extractdir1, super_filenames)
    merge_super_files(extractdir2, super_filenames)
    diff(extractdir1 / "super.img", extractdir2 / "super.img")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())
    diff_release_zips(*sys.argv[1:])
