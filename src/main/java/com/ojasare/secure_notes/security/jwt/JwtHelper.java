package com.ojasare.secure_notes.security.jwt;

import com.ojasare.secure_notes.security.jwt.constant.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ojasare.secure_notes.security.jwt.constant.JWTUtil.*;

@Component
@Slf4j
public class JwtHelper {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtHelper(RsaKeyProperties rsaKeys) {
        this.privateKey = rsaKeys.privateKey();
        this.publicKey = rsaKeys.publicKey();
    }

    public String generateAccessToken(String usernameOrEmail, List<String> roles) {
        return Jwts.builder()
                .subject(usernameOrEmail)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRE_ACCESS_TOKEN))
                .issuer(ISSUER)
                .claim("roles", roles)
                .signWith(privateKey)
                .compact();
    }

    public String generateRefreshToken(String usernameOrEmail) {
        return Jwts.builder()
                .issuer(ISSUER)
                .subject(usernameOrEmail)
                .expiration(new Date(System.currentTimeMillis() + EXPIRE_REFRESH_TOKEN))
                .signWith(privateKey)
                .compact();
    }

    public String extractTokenFromHeaderIfExists(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            return authorizationHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    public Map<String, String> getTokensMap(String jwtAccessToken, String jwtRefreshToken) {
        Map<String, String> idTokens = new HashMap<>();
        idTokens.put("access_token", jwtAccessToken);
        idTokens.put("refresh_token", jwtRefreshToken);
        return idTokens;
    }

    // get username from Jwt token
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
