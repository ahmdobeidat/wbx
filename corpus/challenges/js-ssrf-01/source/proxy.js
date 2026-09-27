const http = require("http");
const express = require("express");
const app = express();
app.get("/fetch", (req, res) => {
  const target = req.query.url;
  http.get(target, (up) => { up.pipe(res); });
});
app.listen(3000);
