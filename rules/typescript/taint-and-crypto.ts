// Test fixture for semgrep --test: annotated examples, never compiled or run.
import { exec, execFile } from "node:child_process";
import * as crypto from "node:crypto";
import express from "express";
import { Pool } from "pg";

const app = express();
const db = new Pool();

app.get("/ping", (req, res) => {
  const host = req.query.host as string;
  // ruleid: ts-tainted-shell
  exec(`ping -c 1 ${host}`);
  // ruleid: ts-tainted-shell
  exec("nslookup " + req.params.name);
  // ok: ts-tainted-shell
  execFile("ping", ["-c", "1", host]);
  const count = parseInt(req.query.count as string, 10);
  // ok: ts-tainted-shell
  exec(`ping -c ${count} localhost`);
  // ok: ts-tainted-shell
  exec("uptime");
  res.send("ok");
});

app.post("/users", async (req, res) => {
  const name = req.body.name;
  // ruleid: ts-tainted-sql
  await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ruleid: ts-tainted-sql
  await db.query("DELETE FROM users WHERE id = " + req.params.id);
  // ok: ts-tainted-sql
  await db.query("SELECT * FROM users WHERE name = $1", [name]);
  const limit = Number(req.query.limit);
  // ok: ts-tainted-sql
  await db.query(`SELECT * FROM users LIMIT ${limit}`);
  res.send("ok");
});

export function digests(data: string): void {
  // ruleid: ts-weak-crypto
  crypto.createHash("md5").update(data).digest("hex");
  // ruleid: ts-weak-crypto
  crypto.createHash("sha1");
  // ruleid: ts-weak-crypto
  crypto.createCipheriv("aes-128-ecb", Buffer.alloc(16), null);
  // ruleid: ts-weak-crypto
  const resetToken = Math.random().toString(36).slice(2);
  // ok: ts-weak-crypto
  crypto.createHash("sha256").update(data).digest("hex");
  // ok: ts-weak-crypto
  crypto.createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12));
  // ok: ts-weak-crypto
  const jitter = Math.random() * 100;
  console.log(resetToken, jitter);
}
