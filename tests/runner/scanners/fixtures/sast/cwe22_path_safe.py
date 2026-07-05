import os
from flask import request

ROOT = "/var/data"

def serve():
    name = request.args.get("name")
    resolved = os.path.realpath(os.path.join(ROOT, name))
    if not resolved.startswith(ROOT):
        return "forbidden", 403
    with open(resolved) as f:
        return f.read()
