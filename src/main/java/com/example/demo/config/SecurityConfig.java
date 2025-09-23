package com.example.demo.config;

import com.example.demo.config.auth.PrincipalDetailsService;
import com.example.demo.config.auth.exceptionHandler.CustomAccessDeniedHandler;
import com.example.demo.config.auth.exceptionHandler.CustomAuthenticationEntryPoint;
import com.example.demo.config.auth.jwt.JwtAuthorizationFilter;
import com.example.demo.config.auth.jwt.JwtProperties;
import com.example.demo.config.auth.jwt.JwtTokenProvider;
import com.example.demo.config.auth.loginHandler.CustomAuthenticationFailureHandler;
import com.example.demo.config.auth.loginHandler.CustomLoginSuccessHandler;
import com.example.demo.config.auth.loginHandler.Oauth2JwtLoginSuccessHandler;
import com.example.demo.config.auth.logoutHandler.CustomLogoutHandler;
import com.example.demo.config.auth.logoutHandler.CustomLogoutSuccessHandler;
import com.example.demo.domain.repository.JWTTokenRepository;
import com.example.demo.domain.repository.UserRepository;
import com.example.demo.domain.sevice.OAuthUnlinkService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final PrincipalDetailsService principalDetailsService;
    private final OAuthUnlinkService oAuthUnlinkService;

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;



    public SecurityConfig(PrincipalDetailsService principalDetailsService, OAuthUnlinkService oAuthUnlinkService, UserRepository userRepository, JwtTokenProvider jwtTokenProvider) {
        this.principalDetailsService = principalDetailsService;
        this.oAuthUnlinkService = oAuthUnlinkService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
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


    // CustomLogoutHandler Bean
    @Bean
    public CustomLogoutHandler customLogoutHandler(JwtTokenProvider jwtTokenProvider,
                                                   JWTTokenRepository jwtTokenRepository,
                                                   PersistentTokenRepository persistentTokenRepository,
                                                   OAuthUnlinkService oAuthUnlinkService,
                                                   @Value("${NAVER_CLIENT_ID}") String naverClientId,
                                                   @Value("${NAVER_CLIENT_SECRET}") String naverClientSecret) {
        return new CustomLogoutHandler(jwtTokenProvider, jwtTokenRepository, oAuthUnlinkService, persistentTokenRepository, naverClientId, naverClientSecret);
    }

    // JwtAuthorizationFilter Bean
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(jwtTokenProvider, userRepository);
    }



    // SecurityFilterChain
    @Bean
    public SecurityFilterChain config(HttpSecurity http, CustomLogoutHandler customLogoutHandler, JwtAuthorizationFilter jwtAuthorizationFilter, CustomLoginSuccessHandler customLoginSuccessHandler, Oauth2JwtLoginSuccessHandler oauth2JwtLoginSuccessHandler,CustomLogoutSuccessHandler customLogoutSuccessHandler) throws Exception{

        // csrf 비활성화
        http.csrf((config -> {config.disable();}));

        // 접근 제한
        http.authorizeHttpRequests((auth) -> {
            auth.requestMatchers("/","/join", "/join/**","/login").permitAll();
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
            login.successHandler(customLoginSuccessHandler);
            login.failureHandler(new CustomAuthenticationFailureHandler());
        });


        // logout
        http.logout((logout) -> {
            logout.permitAll();
            logout.logoutUrl("/logout");
            logout.addLogoutHandler(customLogoutHandler);
            logout.logoutSuccessHandler(customLogoutSuccessHandler);

            // JWT
            logout.deleteCookies("JSESSIONID", JwtProperties.COOKIE_NAME);
            logout.invalidateHttpSession(true);
        });


        // exception
        http.exceptionHandling((exception) -> {
           exception.accessDeniedHandler(new CustomAccessDeniedHandler());
           exception.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
        });


        // oauth2-client
        http.oauth2Login((oauh2) -> {
           oauh2.loginPage("/login");
           oauh2.successHandler(oauth2JwtLoginSuccessHandler);
        });


        // remember me
        http.rememberMe((rm) -> {
           rm.key("rememberMeKey");
           rm.rememberMeParameter("remember-me"); // checkbox name(login form에서)
           rm.alwaysRemember(false);              // 사용자가 체크박스 안 눌렀으면 remember-me 기능 비활성화
           rm.tokenValiditySeconds(60 * 60);
           rm.tokenRepository(tokenRepository()); //  DB에 토큰 저장하는 Repository
        });


        // SESSION INVALIDATE.. 무호화작업
        http.sessionManagement(

                // JSESSIONID 아예 생성되지 않거나, 생성되었다가 곧바로 삭제됨
                httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
        );


        // JWT 필터 추가 (Bean 사용)
        http.addFilterBefore(jwtAuthorizationFilter, BasicAuthenticationFilter.class);



        return http.build();
    }

}