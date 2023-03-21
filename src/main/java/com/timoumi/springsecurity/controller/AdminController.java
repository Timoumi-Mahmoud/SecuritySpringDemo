package com.timoumi.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;
@Controller
@RequestMapping("admin")
public class AdminController {

    @GetMapping("index")
    public String index(){
        return "admin/index";
    }
}
