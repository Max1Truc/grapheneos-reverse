import http.client
import json
import sys
from pathlib import Path

DATA_FILENAME = Path(sys.argv[0]).parent.parent / "build_timestamps.json"


def usage():
    print(
        "Usage:\n"
        " update_build_timestamps.py fetch # to fetch the build timestamp of current releases\n"
        " update_build_timestamps.py extract filename # to fetch the build timestamp of current releases"
    )
    exit(1)


def load_data():
    try:
        data = open(DATA_FILENAME).read()
    except FileNotFoundError:
        data = "{}"
    return json.loads(data)


def save_data(data: dict):
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    open(DATA_FILENAME, "w").write(content)


def fetch():
    data = load_data()

    # this is just for the Pixel 9a, as all
    #   devices share the same build timestamps
    codename = "tegu"

    # all public-facing release channels
    # ignores "testing" as it sometimes contains
    # test releases that are not intended for general use
    channels = ["alpha", "beta", "stable"]

    # security preview releases use a specific suffix
    suffixes = ["", "-security-preview"]

    for channel in channels:
        for suffix in suffixes:
            path = f"/{codename}-{channel}{suffix}"
            print(repr(path))

            conn = http.client.HTTPSConnection("releases.grapheneos.org")
            conn.request("GET", path)
            resp = conn.getresponse()
            assert resp.status == 200
            parts = resp.read().decode().rstrip("\n").split(r" ")
            version, timestamp, received_codename, received_channel = parts
            assert received_codename == codename
            assert received_channel == channel + suffix
            if version not in data:
                data[version] = timestamp
            assert data[version] == timestamp

    save_data(data)


def main(verb, filename=None):
    match sys.argv[1]:
        case "fetch":
            if filename is not None:
                usage()
            fetch()
        case "extract":
            if filename is None:
                usage()
            extract(filename)
        case _:
            usage()


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        usage()
    main(*sys.argv[1:])
