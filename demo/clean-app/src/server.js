const express = require('express');
const { escapeHtml } = require('./escape');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/greet', (req, res) => {
  const name = typeof req.query.name === 'string' ? req.query.name : 'world';
  res.type('text/plain').send('Hello ' + escapeHtml(name));
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', message: err.message }));
  res.status(500).json({ error: 'internal' });
});

if (require.main === module) {
  app.listen(Number(process.env.PORT) || 3000);
}

module.exports = app;
