package com.ojasare.secure_notes.security;

import com.ojasare.secure_notes.security.jwt.JWTAuthenticationFilter;
import com.ojasare.secure_notes.security.jwt.JWTAuthorizationFilter;
import com.ojasare.secure_notes.security.jwt.JwtHelper;
import com.ojasare.secure_notes.security.userConfig.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true)
public class SecurityConfig {

    private final JwtHelper jwtHelper;

    private final UserDetailsServiceImpl userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        configureCSRF(http);
        configureHttpRequests(http);
        configureSessionManagement(http);
        configureAuthenticationFilter(http);
        configureAuthorizationFilter(http);
        configureOAuth2Login(http);
        return http.build();
    }

    private void configureCSRF(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/auth/public/**")
        );
    }

    private void configureSessionManagement(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS));
    }

    private void configureHttpRequests(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests)
                ->  requests
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/csrf-token").permitAll()
                .requestMatchers("/api/auth/public/**").permitAll()
                .requestMatchers("/oauth/authorize").permitAll()
                .anyRequest().authenticated());
    }

    private void configureAuthenticationFilter(HttpSecurity http) throws Exception {
        http.addFilter(new JWTAuthenticationFilter(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)), jwtHelper));
    }

    private void configureAuthorizationFilter(HttpSecurity http) throws Exception {
        http.addFilterBefore(new JWTAuthorizationFilter(jwtHelper, userDetailsService), UsernamePasswordAuthenticationFilter.class);
    }


    private void configureOAuth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/api/auth/login")
                .successHandler((request, response, authentication) -> response.sendRedirect("/api/auth/profile")))
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout").logoutSuccessUrl("/api/auth/login").permitAll());
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}