package com.timoumi.springsecurity.repository;


import com.timoumi.springsecurity.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class DbInit  implements CommandLineRunner {
    @Autowired
    UserRepository userRepository;
    @Autowired
   PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        this.userRepository.deleteAll();


        User mahmoud = new User("mahmoud", passwordEncoder.encode ("mahmoud123"), "USER", "");
        User admin =new User("admin",  passwordEncoder.encode ("admin123"), "ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        User manager= new User("manager", passwordEncoder.encode("manager123"), "MANAGEMENT","ACCESS_TEST1");
        List<User> users = Arrays.asList(mahmoud, admin, manager);

        this.userRepository.saveAll(users);

    }
}
