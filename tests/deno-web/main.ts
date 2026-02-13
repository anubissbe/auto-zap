Deno.serve({ port: 8000 }, () => new Response("<h1>Hello from Deno</h1>", {
  headers: { "content-type": "text/html" }
}));
