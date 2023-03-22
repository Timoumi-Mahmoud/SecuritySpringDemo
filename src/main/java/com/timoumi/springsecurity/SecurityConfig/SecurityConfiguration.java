package com.timoumi.springsecurity.SecurityConfig;


import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import com.timoumi.springsecurity.entity.predifinedClasses.UserPrincipalDetailsService;
import com.timoumi.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private UserRepository userRepository;
   // private BasicAuthenticationEntryPoint basicAuthenticationEntryPoint;
    private UserPrincipalDetailsService userPrincipalDetailsService;

    public SecurityConfiguration(UserPrincipalDetailsService userPrincipalDetailsService , UserRepository userRepository /*,BasicAuthenticationEntryPoint basicAuthenticationEntryPoint*/) {
        this.userPrincipalDetailsService = userPrincipalDetailsService;
        this.userRepository= userRepository;
     //   this.basicAuthenticationEntryPoint= basicAuthenticationEntryPoint;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                //remove csrf and state in session because jwt  do not need  them

                .and()
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), this.userRepository))
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/api/public/management/*").hasRole("MANAGEMENT")
                .antMatchers("/api/public/admin/*").hasRole("ADMIN")

        ;


                /*
                .authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/api/public/test").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                .and()
                .formLogin()
                .loginProcessingUrl("/signin")
                .loginPage("/login").permitAll()
                .usernameParameter("txtUsername")
                .passwordParameter("txtPassword")
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/login")
                .and()
                .rememberMe().tokenValiditySeconds(2592000).key("mySecret!").userDetailsService(userPrincipalDetailsService).rememberMeParameter("checkRememberMe");

    */
    }

        //  "/path/**"
        //the order of antMatchers is so important for example if i put  anyRequest().permetAll() at the beginning of the chain






    @Bean
    DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);

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
