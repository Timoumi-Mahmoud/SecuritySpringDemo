package com.timoumi.springsecurity.SecurityConfig;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.timoumi.springsecurity.SecurityConfig.JwtProperties;
import com.timoumi.springsecurity.entity.LoginViewModel;
import com.timoumi.springsecurity.entity.predifinedClasses.UserPrincipal;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

//later on
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;


   public JwtAuthenticationFilter(AuthenticationManager authenticationManager){
       this.authenticationManager= authenticationManager;
   }


   ///Trigger when we issue Post request to /login
    /*
    we also need to pass in {"username":"mahmoud", "password":"mahmoud123"} in the request body
,      */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
       // return super.attemptAuthentication(request, response);


        // Grab credentials and map them to login viewmodel
        LoginViewModel credentials = null;
        try {
            credentials = new ObjectMapper().readValue(request.getInputStream(), LoginViewModel.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Create login token
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                credentials.getUsername(),
                credentials.getPassword(),
                new ArrayList<>());

        // Authenticate user
        Authentication auth = authenticationManager.authenticate(authenticationToken);

        return auth;



   }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
       // super.successfulAuthentication(request, response, chain, authResult);
        // Grab principal(man in the midel between Spring security and our app) instance ==> from authentication result
        UserPrincipal principal = (UserPrincipal) authResult.getPrincipal();

        // Create JWT Token
        String token = JWT.create()
                .withSubject(principal.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));

        // Add token in response
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + token);
    }
}
