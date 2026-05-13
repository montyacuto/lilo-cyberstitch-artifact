const express = require("express");
const childProcess = require("child_process");

const app = express();

app.get("/exec", (req, res) => {
  childProcess.exec(req.query.cmd, (_err, stdout) => res.send(stdout));
});

app.get("/exec-sync", (req, res) => {
  const stdout = childProcess.execSync(req.query.cmd);
  res.send(stdout.toString());
});

app.get("/eval", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

module.exports = app;
