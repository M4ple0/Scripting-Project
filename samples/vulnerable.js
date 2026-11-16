// Deliberately insecure demo - input for the scanner.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
const password = "hunter2hunter2";
app.use(cors({ origin: "*", credentials: true }));

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => res.json(rows));
});

app.get("/run", (req, res) => {
  exec("convert " + req.query.file + " out.png");
  res.send("ok");
});

app.post("/eval", (req, res) => {
  res.send(String(eval(req.body.code)));
});

app.get("/token", (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  res.send(resetToken);
});

const digest = crypto.createHash("md5").update(password).digest("hex");
document.getElementById("out").innerHTML = location.hash.substring(1);
