#!/usr/bin/env python3
"""Stand-in for `ssh-add -L` in tests: prints the keys in argv[1] and exits with argv[2]
(0 = keys listed, 1 = agent reachable but empty, 2 = agent unreachable)."""
import sys

code = int(sys.argv[2]) if len(sys.argv) > 2 else 0
if code == 0:
    with open(sys.argv[1], encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
elif code == 1:
    print("The agent has no identities.")
else:
    print("Error connecting to agent: No such file or directory", file=sys.stderr)
sys.exit(code)
