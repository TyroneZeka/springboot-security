package org.mufasadev.core.springsecurity.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {
    @GetMapping("/hello")
    public ResponseEntity<String> greeting() {
        return ResponseEntity.ok("Hello " + "World" + "!");
    }
}
