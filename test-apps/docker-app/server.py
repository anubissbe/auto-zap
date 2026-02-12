from http.server import HTTPServer, SimpleHTTPRequestHandler
import io

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        if self.path == '/about':
            self.wfile.write(b'<html><body><h1>About</h1><a href="/">Home</a></body></html>')
        else:
            self.wfile.write(b'<html><body><h1>Docker App Test</h1><a href="/about">About</a></body></html>')

HTTPServer(('0.0.0.0', 3000), Handler).serve_forever()
