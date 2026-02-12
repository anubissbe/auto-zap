package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			fmt.Fprint(w, "<html><body><h1>About</h1><a href=\"/\">Home</a></body></html>")
			return
		}
		fmt.Fprint(w, "<html><body><h1>Go Web Test</h1><a href=\"/about\">About</a></body></html>")
	})

	fmt.Println("Go web running on port 8080")
	http.ListenAndServe("0.0.0.0:8080", nil)
}
