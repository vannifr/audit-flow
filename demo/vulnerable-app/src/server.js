const express = require('express');
const _ = require('lodash');
const { login } = require('./auth');
const db = require('./db');

const app = express();
app.use(express.json());

app.get('/users', (req, res) => {
  const rows = db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  res.json(rows);
});

app.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.post('/login', (req, res) => {
  console.log('login attempt', req.body.email, req.body.password, req.body.phone);
  const result = login(req.body.user, req.body.password);
  res.json(result || { error: 'denied' });
});

app.post('/settings', (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

app.listen(3000);
