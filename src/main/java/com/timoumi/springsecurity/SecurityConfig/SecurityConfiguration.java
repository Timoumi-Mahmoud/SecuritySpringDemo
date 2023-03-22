package com.timoumi.springsecurity.SecurityConfig;


import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import com.timoumi.springsecurity.entity.predifinedClasses.UserPrincipalDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private UserPrincipalDetailsService userPrincipalDetailsService;

    public SecurityConfiguration(UserPrincipalDetailsService userPrincipalDetailsService) {
        this.userPrincipalDetailsService = userPrincipalDetailsService;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {


        auth.authenticationProvider(authenticationProvider());
        System.out.println("\n "+ auth);



    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

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
                .antMatchers("/api/public/users").hasRole("ADMIN")

                .and()
                .httpBasic();
        //  "/path/**"
        //the order of antMatchers is so important for example if i put  anyRequest().permetAll() at the beginning of the chain




    }


    @Bean
    DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);

        System.out.println("\n heererererr \n "+ userPrincipalDetailsService);
        return daoAuthenticationProvider;
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
