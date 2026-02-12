const fastify = require('fastify')({ logger: false });
const PORT = process.env.PORT || 3000;

fastify.get('/', async (request, reply) => {
  reply.type('text/html').send('<html><body><h1>Fastify Test</h1><a href="/about">About</a></body></html>');
});

fastify.get('/about', async (request, reply) => {
  reply.type('text/html').send('<html><body><h1>About</h1><a href="/">Home</a></body></html>');
});

fastify.listen({ port: PORT, host: '0.0.0.0' }, (err) => {
  if (err) { console.error(err); process.exit(1); }
  console.log(`Fastify running on port ${PORT}`);
});
