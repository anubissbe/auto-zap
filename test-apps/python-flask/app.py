from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return '<html><body><h1>Flask Test</h1><a href="/about">About</a></body></html>'

@app.route('/about')
def about():
    return '<html><body><h1>About</h1><a href="/">Home</a></body></html>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
