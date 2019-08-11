const express = require("express");
const app = express();
const port = 19583;
const sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database("data.sl3");

app.get("/ping", (req, res) => {
    res.send("pong");
});

app.listen(port, () => {
    console.log("auth-server listening on port " + port);
});
