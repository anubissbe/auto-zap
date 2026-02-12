package com.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @GetMapping(value = "/", produces = "text/html")
    public String home() {
        return "<html><body><h1>Spring Boot Test</h1><a href=\"/about\">About</a></body></html>";
    }

    @GetMapping(value = "/about", produces = "text/html")
    public String about() {
        return "<html><body><h1>About</h1><a href=\"/\">Home</a></body></html>";
    }
}
