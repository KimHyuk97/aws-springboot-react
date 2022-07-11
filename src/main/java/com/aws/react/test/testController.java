package com.aws.react.test;

import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class testController {
    @GetMapping("hello")
    public Map<String, String> index() {
        Map<String, String> map = new HashMap<>();
        map.put("data", "hello");
        map.put("data2", "hello2");

        return map;
    }
    
}
