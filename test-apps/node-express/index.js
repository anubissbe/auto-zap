const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('<html><body><h1>Express Test</h1><a href="/about">About</a></body></html>');
});

app.get('/about', (req, res) => {
  res.send('<html><body><h1>About</h1><a href="/">Home</a></body></html>');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Express running on port ${PORT}`);
});
