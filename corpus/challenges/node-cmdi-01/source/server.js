const express = require("express");
const cp = require("child_process");
const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host;
  cp.exec("ping -c 1 " + host, (e, out) => {   // command injection sink
    res.send(out);
  });
});

app.listen(3000);
