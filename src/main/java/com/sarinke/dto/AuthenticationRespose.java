package com.sarinke.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
@Setter
@Getter
@AllArgsConstructor
public class AuthenticationRespose {
    private String accessToken;
    private String refreshToken;
    private Collection<? extends GrantedAuthority> authorities;
}
