#!/usr/bin/env python3

from __future__ import annotations

from vulnerabilitylookup import VulnerabilityLookup

vl = VulnerabilityLookup()


def reimport_feed() -> None:
    for source in vl.get_sources():
        data = input(
            f"Do you want to reimport {source} from scratch?\n\tIf yes, type the name of the source. Otherwise, hit enter."
        )
        if data == source:
            if vl.del_source(source):
                print(f"{source} deleted.")
            else:
                print(f"Unable to delete {source}")
        else:
            print(f"*not* deleting {source}")


if __name__ == "__main__":
    print(
        "Any feed you remove with this script will be reimported from scratch next time the feeder runs."
    )
    reimport_feed()
