#!/usr/bin/env python3

import argparse
import kconfiglib

def main():
    parser = argparse.ArgumentParser(description="Export full defconfig: include the default options")
    parser.add_argument("--kconfig", default="Kconfig", help="Top-level Kconfig file (default: Kconfig)")
    parser.add_argument("--out", default="defconfig", help="Output filename (default: defconfig)")
    args = parser.parse_args()

    kconf = kconfiglib.Kconfig(args.kconfig, suppress_traceback=True)
    kconf.load_config()

    # Step 1: get full config string
    contents = kconf._config_contents(None)

    # Step 2: only keep the CONFIG_ lines
    lines = contents.splitlines()
    cleaned = [line for line in lines if line.startswith("CONFIG_")]

    # Step 3: write to file
    with open(args.out, "w") as f:
        for line in cleaned:
            f.write(line + "\n")

    print(f"full defconfig saved to {args.out}")

if __name__ == "__main__":
    main()