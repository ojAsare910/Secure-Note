package com.ojasare.secure_notes.security.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String username;
    private List<String> roles;
    private String jwtAccessToken;
    private String jwtRefreshToken;
}
