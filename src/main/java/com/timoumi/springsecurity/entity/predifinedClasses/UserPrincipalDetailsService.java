package com.timoumi.springsecurity.entity.predifinedClasses;

import com.timoumi.springsecurity.entity.User;
import com.timoumi.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;




    @Service
    public class UserPrincipalDetailsService implements UserDetailsService {
        private UserRepository userRepository;

        public UserPrincipalDetailsService(UserRepository userRepository) {
            this.userRepository = userRepository;
        }


        @Override
        public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
            User user = this.userRepository.findByUsername(s);
            UserPrincipal userPrincipal = new UserPrincipal(user);

            return userPrincipal;
        }
    }