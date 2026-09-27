const express = require("express");
const app = express();
app.get("/admin/users", (req, res) => { res.json(listAllUsers()); });
app.post("/admin/delete", (req, res) => { res.send(deleteUser(req.body.id)); });
function listAllUsers() { return []; }
function deleteUser(id) { return "ok"; }
app.listen(3000);
