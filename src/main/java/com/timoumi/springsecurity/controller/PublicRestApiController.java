package com.timoumi.springsecurity.controller;

import com.timoumi.springsecurity.entity.User;
import com.timoumi.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/public")

public class PublicRestApiController {
@Autowired
     UserRepository userRepository;


    public PublicRestApiController(){}

    @GetMapping("test1")
    public String test1(){
        return "API Test 1";
    }

    @GetMapping("test2")
    public String test2(){
        return "API Test 2";
    }

@GetMapping("users")
    public List<User> allUsers(){
return userRepository.findAll();
    }

}