import subprocess
from flask import request

def ping():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)
