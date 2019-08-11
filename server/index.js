const express = require('express');
const app = express();
const port = 19583;

app.get('/ping', (req, res) => {
    res.send('pong');
});

app.listen(port, () => {
    console.log("auth-server listening on port " + port);
});
