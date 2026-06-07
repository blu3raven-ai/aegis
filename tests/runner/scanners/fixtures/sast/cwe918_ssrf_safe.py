import requests
from flask import request

ALLOWLIST = ["https://api.example.com", "https://cdn.example.com"]

def fetch():
    url = request.args.get("url")
    if not any(url.startswith(allowed) for allowed in ALLOWLIST):
        return "forbidden", 403
    return requests.get(url).text
