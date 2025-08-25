package com.example.demo.config;

import com.example.demo.config.auth.PrincipalDetailsService;
import com.example.demo.config.auth.exceptionHandler.CustomAccessDeniedHandler;
import com.example.demo.config.auth.exceptionHandler.CustomAuthenticationEntryPoint;
import com.example.demo.config.auth.loginHandler.CustomAuthenticationFailureHandler;
import com.example.demo.config.auth.loginHandler.CustomLoginSuccessHandler;
import com.example.demo.config.auth.logoutHandler.customLogoutHandler;
import com.example.demo.config.auth.logoutHandler.customLogoutSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalDetailsService principalDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain config(HttpSecurity http) throws Exception{

        // csrf 비활성화
        http.csrf((config -> {config.disable();}));


        // 접근 제한
        http.authorizeHttpRequests((auth) -> {
            auth.requestMatchers("/","/join","/login").permitAll();
            auth.requestMatchers("/user").hasRole("USER");
            auth.requestMatchers("/admin").hasRole("ADMIN");
            auth.anyRequest().authenticated();
        });

        // login
        http.formLogin((login) -> {
            login.permitAll();
            login.loginPage("/login");
            login.usernameParameter("email");              // username → email [로그인 요청 시 email 필드를 username 대신 사용]
            login.passwordParameter("password");           // password 그대로
            login.successHandler(new CustomLoginSuccessHandler());
            login.failureHandler(new CustomAuthenticationFailureHandler());
        });


        // logout
        http.logout((logout) -> {
            logout.permitAll();
            logout.logoutUrl("/logout");
            logout.addLogoutHandler(new customLogoutHandler());
            logout.logoutSuccessHandler(new customLogoutSuccessHandler());
        });


        // exception
        http.exceptionHandling((exception) -> {
           exception.accessDeniedHandler(new CustomAccessDeniedHandler());
           exception.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
        });


        // oauth2-client
        http.oauth2Login((oauh2) -> {
           oauh2.loginPage("/login");
        });


        // remember me
        http.rememberMe((rm) -> {
           rm.key("rememberMeKey");
           rm.rememberMeParameter("remember-me"); // checkbox name(login form에서)
           rm.alwaysRemember(false);              // 사용자가 체크박스 안 눌렀으면 remember-me 기능 비활성화
           rm.tokenValiditySeconds(60 * 60);
           rm.tokenRepository(tokenRepository()); //  DB에 토큰 저장하는 Repository
        });
        return http.build();
    }

    // DB 기반 Remember-Me 토큰 저장소를 설정
    @Autowired
    private DataSource dataSource;
    @Bean
    public PersistentTokenRepository tokenRepository(){
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }



}