import os
import shlex
import sqlite3
import subprocess

from fastapi import FastAPI
from flask import Flask, request

app = Flask(__name__)
api = FastAPI()
db = sqlite3.connect(":memory:")


@app.get("/user")
def flask_user():
    user_id = request.args.get("id")
    cur = db.cursor()
    # ruleid: python-tainted-sql
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    query = "SELECT * FROM users WHERE name = '" + request.form["name"] + "'"
    # ruleid: python-tainted-sql
    cur.execute(query)
    # ok: python-tainted-sql
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # ok: python-tainted-sql
    cur.execute(f"SELECT * FROM users WHERE id = {int(user_id)}")
    table = "users"
    # ok: python-tainted-sql
    cur.execute(f"SELECT count(*) FROM {table}")
    return "ok"


def django_view(request):
    name = request.GET["name"]
    # ruleid: python-tainted-sql
    db.execute("DELETE FROM users WHERE name = '%s'" % name)
    # ok: python-tainted-sql
    db.execute("DELETE FROM users WHERE name = %s", [name])


@api.get("/items/{item_id}")
async def fastapi_item(item_id: str, limit: int):
    # ruleid: python-tainted-sql
    db.execute(f"SELECT * FROM items WHERE id = '{item_id}'")
    # ok: python-tainted-sql
    db.execute(f"SELECT * FROM items LIMIT {limit}")
    # ok: python-tainted-sql
    db.execute("SELECT * FROM items WHERE id = ?", (item_id,))


@app.post("/ping")
def ping():
    host = request.json["host"]
    # ruleid: python-tainted-shell
    os.system("ping -c 1 " + host)
    # ruleid: python-tainted-shell
    subprocess.run(f"ping -c 1 {host}", shell=True, check=True)
    # ruleid: python-tainted-shell
    subprocess.run(["sh", "-c", "ping " + host], check=True)
    # ok: python-tainted-shell
    subprocess.run(["ping", "-c", "1", host], check=True)
    # ok: python-tainted-shell
    os.system("ping -c 1 " + shlex.quote(host))
    # ok: python-tainted-shell
    subprocess.run("uptime", shell=True, check=True)
    count = int(request.args["count"])
    # ok: python-tainted-shell
    os.system(f"ping -c {count} localhost")
    return "ok"
