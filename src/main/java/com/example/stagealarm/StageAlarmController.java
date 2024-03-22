package com.example.stagealarm;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/hello")
public class StageAlarmController {
    @GetMapping
    public String hello() {
        return "content/hello";
    }


}