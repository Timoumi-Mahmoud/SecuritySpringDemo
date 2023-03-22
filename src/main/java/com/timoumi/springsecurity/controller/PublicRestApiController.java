package com.timoumi.springsecurity.controller;

import com.timoumi.springsecurity.entity.User;
import com.timoumi.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/public")
@CrossOrigin
public class PublicRestApiController {
@Autowired
     UserRepository userRepository;


    public PublicRestApiController(){}
//Available to all authenticated users
    @GetMapping("test")
    public String test1(){
        return "API Test ";
    }

    //available to managers
    @GetMapping("management/reports")
    public String test2(){
        return "Some report data ";
    }
//Available to admin
@GetMapping("admin/users")
    public List<User> allUsers(){
return userRepository.findAll();
    }

}