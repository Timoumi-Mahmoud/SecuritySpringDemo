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
                .withUser("admin").
                password(passwordEncoder().encode(  "admin123")).
                roles("ADMIN")
                .authorities("ACCESS_TEST1", "ACCESS_TEST1")


                .and().
                withUser("mahmoud").
                password( passwordEncoder().encode("mahmoud123")).
                roles("USER")

                .and().
                withUser("manager").
                password(passwordEncoder().encode("manager123")).
                roles("MANAGEMENT").
                authorities("ACCESS_TEST1")
        ;
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
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGEMENT")
                //protecting Resources not views
                //.antMatchers("/api/public/**").authenticated() //hasRole work too
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                 //.antMatchers("/api/public/test1").authenticated()

                .and()
                .httpBasic();
        //  "/path/**"
        //the order of antMatchers is so important for example if i put  anyRequest().permetAll() at the beginning of the chain


    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new  BCryptPasswordEncoder();
    }



    //Enable SSL/HTTPS
    /*
    steps:
     1)certificate (self signed or buy
     2) Modify app.properties
     3)add @bean for ServletWebServerFactory(reddirect all http trafic to https)


     .\keytool -genkey -alias bootsecurity -storetype PKCS12 -keyalg RSA -Keysize 2048 -keystore bootsecurity.p12 -validity 3650
     */
}
