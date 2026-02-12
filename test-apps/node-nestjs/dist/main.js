// Simulates compiled NestJS output - plain HTTP server for testing
const http = require('http');
const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  if (req.url === '/about') {
    res.end('<html><body><h1>About</h1><a href="/">Home</a></body></html>');
  } else {
    res.end('<html><body><h1>NestJS Test</h1><a href="/about">About</a></body></html>');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`NestJS (simulated) running on port ${PORT}`);
});
