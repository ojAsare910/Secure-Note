package com.ojasare.secure_notes.security.jwt;

import com.ojasare.secure_notes.security.userConfig.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.ojasare.secure_notes.security.jwt.constant.JWTUtil.AUTH_HEADER;

@Component
@RequiredArgsConstructor
@Slf4j
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final JwtHelper jwtHelper;

    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("[JWTAuthorizationFilter called for URI: {}]", request.getRequestURI());
       try {
           if (request.getServletPath().equals("/api/auth/public/refresh-token")) {
               filterChain.doFilter(request, response);
           } else {
               String accessToken = jwtHelper.extractTokenFromHeaderIfExists(request.getHeader(AUTH_HEADER));
               if (accessToken != null && jwtHelper.validateJwtToken(accessToken)) {
                   String username = jwtHelper.getUserNameFromJwtToken(accessToken);
                   UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                   UsernamePasswordAuthenticationToken authenticationToken =
                           new UsernamePasswordAuthenticationToken(userDetails,
                                   null,
                                   userDetails.getAuthorities());
                   log.info("Roles from JWT: {}", userDetails.getAuthorities());
                   authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                   SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                   filterChain.doFilter(request, response);
               }
               else {
                   filterChain.doFilter(request, response);
               }
           }
       } catch (Exception e) {
           log.error("Cannot set user authentication: {}", e.getMessage());
       }

    }
}
