from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get('/', response_class=HTMLResponse)
def home():
    return '<html><body><h1>FastAPI Test</h1><a href="/about">About</a></body></html>'

@app.get('/about', response_class=HTMLResponse)
def about():
    return '<html><body><h1>About</h1><a href="/">Home</a></body></html>'
