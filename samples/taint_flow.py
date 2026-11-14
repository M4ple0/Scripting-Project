import os
import subprocess
import sys

from flask import Flask, request

app = Flask(__name__)


def build_command(host):
    return "ping -c 1 " + host


def run_shell(command):
    return os.popen(command).read()


def read_report(name):
    with open(name) as handle:
        return handle.read()


@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    command = build_command(host)
    return run_shell(command)


@app.route("/report/<name>")
def report(name):
    return read_report(name)


def main():
    target = sys.argv[1]
    subprocess.run(
        "nslookup " + target,
        shell=True,
    )
    count = int(input("how many? "))
    subprocess.run(["sleep", str(count)])
    note = input("note: ")
    print(note.strip())
