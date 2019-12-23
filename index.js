// Main starting point of the application
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const router = require('./router');
const mongoose = require('mongoose');

// db setup
mongoose
  .connect('mongodb://localhost:auth/auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(console.log('cnonected'))
  .catch(err => {
    console.log(err);
  });

const app = express();

app.use(morgan('combined'));
app.use(bodyParser.json({ type: '*/*' }));
router(app);

const port = process.env.PORT || 3090;
const server = http.createServer(app);

server.listen(port);
console.log('Server listening on ' + port);
