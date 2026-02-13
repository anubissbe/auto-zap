const fastify = require('fastify')();
fastify.get('/', async () => ({ hello: 'fastify' }));
fastify.listen({ port: 3000, host: '0.0.0.0' });
