"""Hardened counterpart of vulnerable_app.py - the scanner should stay quiet here."""
import ast
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile

import bcrypt
import requests
import yaml
from flask import Flask, render_template, request

app = Flask(__name__)
BASE_DIR = "/var/data"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)
    return "done"


@app.route("/calc")
def calc():
    return str(ast.literal_eval(request.args.get("expr", "0")))


@app.route("/load", methods=["POST"])
def load():
    obj = json.loads(request.data)
    cfg = yaml.safe_load(request.data)
    return str(obj) + str(cfg)


@app.route("/file")
def read_file():
    safe_name = os.path.basename(request.args["name"])
    full_path = os.path.join(BASE_DIR, safe_name)
    with open(full_path) as handle:
        return handle.read()


@app.route("/hello")
def hello():
    return render_template("hello.html", name=request.args.get("n", ""))


def make_reset_link(user):
    reset_token = secrets.token_urlsafe(32)
    return "https://example.org/reset?t=" + reset_token


def store_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def login(username, password, stored_hash):
    return hmac.compare_digest(store_password(password), stored_hash)


def fetch(url):
    return requests.get(url, timeout=10)


def save(data):
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(data)
        os.chmod(handle.name, 0o600)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
