from flask import request

def serve():
    name = request.args.get("name")
    with open(name) as f:
        return f.read()
