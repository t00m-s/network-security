#!/usr/bin/env python3
from spoofer import Spoofer


def main() -> None:
    spoofer = Spoofer("example.com", "", "udp and dst port 53")
    spoofer.spoof()


if __name__ == "__main__":
    main()
