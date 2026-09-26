const express = require("express");
const app = express();
app.use(express.json());

function merge(dst, src) {
  for (const k in src) {
    if (typeof src[k] === "object") {
      merge(dst[k], src[k]);
    } else {
      dst[k] = src[k];   // prototype pollution sink (no __proto__ guard)
    }
  }
}

app.post("/merge", (req, res) => {
  const out = {};
  merge(out, req.body);
  res.json(out);
});

app.listen(3000);
