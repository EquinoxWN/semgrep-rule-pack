"""Stand-in for the semgrep binary: behaviour is chosen by the FAKE_SEMGREP variable."""

import json
import os
import sys
import time

mode = os.environ.get("FAKE_SEMGREP", "ok")
if mode == "env":
    keys = ["HOME", "SEMGREP_SEND_METRICS", "SEMGREP_ENABLE_VERSION_CHECK", "SEMGREP_SETTINGS_FILE"]
    print(
        json.dumps(
            {
                "results": [],
                "errors": [],
                "version": json.dumps(
                    {k: os.environ.get(k) for k in keys} | {"argv": sys.argv[1:]}
                ),
            }
        )
    )
elif mode == "sleep":
    time.sleep(30)
elif mode == "crash":
    print("boom: rule pack exploded", file=sys.stderr)
    sys.exit(2)
elif mode == "garbage":
    print("not json")
elif mode == "errors":
    print(json.dumps({"results": [], "errors": [{"message": "Rule parse error in rule x"}]}))
else:
    target = sys.argv[-1]
    result = {
        "check_id": "rules.python.python-demo-rule",
        "path": target,
        "start": {"line": 4},
        "end": {"line": 4},
        "extra": {"severity": "ERROR", "message": "m"},
    }
    print(json.dumps({"results": [result], "errors": [], "version": "fake"}))
    sys.exit(1)
