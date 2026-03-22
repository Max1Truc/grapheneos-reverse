# grapheneos-reverse

## Build GrapheneOS

> [Baseline build dependencies:](https://grapheneos.org/build#build-dependencies)
> - x86_64 Linux build environment
> - 32GiB of memory or more. Link-Time Optimization (LTO) creates huge peaks during linking and is mandatory for Control Flow Integrity (CFI). Linking Vanadium (Chromium) and the Linux kernel with LTO + CFI are the most memory demanding tasks.
> - 100GiB+ of additional free storage space for a typical build of the entire OS for a multiarch device

Let's build release 2026032000 for example.
We'll build it with the security preview version number (2026032001).
This way we can diff the official version (deemed tegu-install-2026032001.zip) and the reproduced version (deemed tegu-install-2026032001-reproduced.zip).

```
$ mkdir -m777 ./build/ # fix a permissions issue
$ docker compose run --build --rm build
[a new shell opens]
reprobuilder@build:$ fetch_source.sh 2026032000
[...]
sync failed, retrying in 1 mn
Syncing: 100% (1032/1032), done in 1m10.703s
Checking for bloat: 100% (131/131), done in 19.209s
repo sync has finished successfully.
reprobuilder@build:$ # get the build values from https://releases.grapheneos.org/tegu-testing-security-preview for example
reprobuilder@build:$ build_source.sh 2026032001 1773969441
```

## Diff GrapheneOS

First, build a normal release with the corresponding security preview build number (e.g. build with 2026032000 source code but with 2026032001 version number).

Then you can diff both files.
Only files that differ will be unpacked, and then their content will be diffed, recursively.

```
$ docker compose run --build --rm diff
[a new shell opens]
reprodiffer@build:$ diff.py releases/tegu-install-2026032001.zip releases/tegu-install-2026032001-reproduced.zip | tee releases/diff.txt
reprodiffer@build:$ exit
```

This will create a `diff.txt` file with the list of all files that changed, in the format `DIFF [file1] [file2]`
All these files will be in `releases/tegu-install-2026032001.d` and `releases/tegu-install-2026032001-reproduced.d`.
