const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const PORT = process.env.PORT || 3000;

const app = new Hono();

app.get('/', (c) => {
  return c.html('<html><body><h1>Hono Test</h1><a href="/about">About</a></body></html>');
});

app.get('/about', (c) => {
  return c.html('<html><body><h1>About</h1><a href="/">Home</a></body></html>');
});

serve({ fetch: app.fetch, port: PORT, hostname: '0.0.0.0' }, () => {
  console.log(`Hono running on port ${PORT}`);
});
