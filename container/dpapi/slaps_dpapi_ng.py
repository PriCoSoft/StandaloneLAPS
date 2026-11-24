#!/usr/bin/env python3
"""DPAPI-NG helper for the SLAPS container server (Linux has no NCryptUnprotectSecret).

Decrypts Windows LAPS blobs (msLAPS-Encrypted* without the 16-byte header) with the dpapi-ng library
(https://github.com/jborean93/dpapi-ng, MIT), the same approach LAPS-WebUI uses. The group key is fetched from a
domain controller over RPC (MS-GKDI) with the service account, which must be allowed by the LAPS policy setting
"Configure authorized password decryptors".

Protocol (stdin -> stdout, both JSON, so no secret appears on the command line):
  in : {"server": "dc01.corp.example", "username": "svc@corp.example", "password": "...",
        "auth": "negotiate", "blobs": ["<base64>", ...]}
  out: {"results": [{"data": "<base64>"} | {"error": "..."}, ...]}  or  {"error": "..."}
"""
import base64
import json
import sys


def main():
    try:
        request = json.load(sys.stdin)
    except Exception as ex:  # noqa: BLE001 - report any malformed input
        json.dump({"error": "invalid request: %s" % ex}, sys.stdout)
        return 2
    try:
        import dpapi_ng
    except ImportError:
        json.dump({"error": "the Python package dpapi-ng is not installed (pip install dpapi-ng)"}, sys.stdout)
        return 3

    kwargs = {}
    for name in ("server", "username", "password"):
        if request.get(name):
            kwargs[name] = request[name]
    if request.get("auth"):
        kwargs["auth_protocol"] = request["auth"]
    # One cache per reveal: the current password and its history usually share one group key, so one RPC call.
    cache = dpapi_ng.KeyCache()
    results = []
    for blob in request.get("blobs", []):
        try:
            data = dpapi_ng.ncrypt_unprotect_secret(base64.b64decode(blob), cache=cache, **kwargs)
            results.append({"data": base64.b64encode(data).decode("ascii")})
        except Exception as ex:  # noqa: BLE001 - every failure is reported per blob
            results.append({"error": "%s: %s" % (type(ex).__name__, ex)})
    json.dump({"results": results}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
