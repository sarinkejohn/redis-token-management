package com.sarinke.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class TokenPair {
    private String accessToken;
    private String refreshToken;
    private String accessJti;
    private String refreshJti;
}
