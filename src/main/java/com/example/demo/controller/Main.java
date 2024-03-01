package com.example.demo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class Main {

    @GetMapping(value = {"/", "/api/"})
    public String main() {
        return "index";
    }
}
