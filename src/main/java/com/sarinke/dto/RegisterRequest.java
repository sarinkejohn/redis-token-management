package com.sarinke.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {
    @NotBlank(message="Username is requred")
    private String username;
    @NotBlank(message = "Pwd required")
    private String password;
}
