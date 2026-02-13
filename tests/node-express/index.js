const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('<h1>Hello from Express</h1>'));
app.listen(3000, '0.0.0.0', () => console.log('Listening on port 3000'));
