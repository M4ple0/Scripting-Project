"""Deliberately insecure demo app - input for the scanner. Never deploy this."""
import hashlib
import os
import pickle
import random
import sqlite3
import ssl
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)
DEBUG = True
ALLOWED_HOSTS = ["*"]
DB_PASSWORD = "Sup3rS3cretPassw0rd"
API_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKE1234"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    subprocess.call("nslookup " + host, shell=True)
    return "done"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str(obj) + str(cfg)


@app.route("/file")
def read_file():
    with open("/var/data/" + request.args["name"]) as handle:
        return handle.read()


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello " + request.args.get("n", "") + "</h1>")


def make_reset_link(user):
    reset_token = str(random.randint(100000, 999999))
    return "https://example.org/reset?t=" + reset_token


def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def login(username, password):
    if password == "admin123":
        return True
    return False


def fetch(url):
    context = ssl._create_unverified_context()
    return requests.get(url, verify=False)


def save(data):
    path = tempfile.mktemp()
    open(path, "w").write(data)
    os.chmod(path, 0o777)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
