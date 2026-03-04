from zipfile import ZipFile
from pathlib import Path
import logging
import os
import sys

logger = logging.getLogger(__name__)


def main(filename1: str, filename2: str):
    zip1 = ZipFile(filename1)
    zip2 = ZipFile(filename2)

    extractdir1 = Path(filename1).with_suffix(".d")
    extractdir2 = Path(filename2).with_suffix(".d")

    for (file1, file2) in zip(zip1.infolist(), zip2.infolist(), strict=True):
        name = file1.filename.split("/", maxsplit=1)[1]
        assert name == file2.filename.split("/", maxsplit=1)[1]

        assert not file1.is_dir()
        assert not file2.is_dir()

        # it's not a cryptographic hash
        # TODO hash the file ourselves
        if file1.CRC == file2.CRC:
            logger.debug("EQUAL " + name)
            continue # skip identical files

        logger.info("DIFF " + name)
        # TODO extract the file

if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO').upper())
    main(*sys.argv[1:])
