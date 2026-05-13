const express = require("express");

const app = express();

const allowed = new Set(["status", "version"]);

app.get("/exec", (req, res) => {
  const command = allowed.has(req.query.cmd) ? req.query.cmd : "status";
  res.send(command);
});

app.get("/exec-sync", (_req, res) => {
  res.send("status");
});

app.get("/eval", (_req, res) => {
  res.send("disabled");
});

module.exports = app;
