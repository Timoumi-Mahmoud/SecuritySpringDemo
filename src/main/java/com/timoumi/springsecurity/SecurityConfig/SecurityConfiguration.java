package com.timoumi.springsecurity.SecurityConfig;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity

public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       // super.configure(auth);

        auth.inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode(  "admin123")).roles("ADMIN")
                .and().withUser("mahmoud").password( passwordEncoder().encode("mahmoud123")  ).roles("MANAGEMENT");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
//authorization
    /*    http.
                authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();*/
        http.
                authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/index").authenticated()
                .antMatchers("/admin/index").hasRole("ADMIN")
                .antMatchers("/management/index").hasAnyRole("ADMIN", "MANAGEMENT")
                .and()
                .httpBasic();
        //  "/path/**"
        //the order of antMatchers is so important for example if i put  anyRequest().permetAll() at the beginning of the chain


    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new  BCryptPasswordEncoder();
    }

}
