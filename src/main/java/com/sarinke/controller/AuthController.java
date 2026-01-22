package com.sarinke.controller;

import com.sarinke.dto.AuthenticationRespose;
import com.sarinke.dto.LoginRequest;
import com.sarinke.dto.RefreshTokenRequest;
import com.sarinke.dto.RegisterRequest;
import com.sarinke.service.AuthService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for authentication endpoints:
 * - Register
 * - Login
 * - Logout
 * - Refresh JWT tokens
 */
@RestController
@AllArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    /**
     * Register a new user.
     *
     * @param request RegisterRequest containing username and password
     * @return ResponseEntity with AuthenticationRespose containing access and refresh tokens
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationRespose> registerNewUser(@Valid @RequestBody RegisterRequest request) {
        AuthenticationRespose authResponse = authService.registerNewUser(request);
        return ResponseEntity.ok(authResponse);
    }

    /**
     * Authenticate an existing user and return JWT tokens.
     *
     * @param loginRequest LoginRequest containing username and password
     * @return ResponseEntity with AuthenticationRespose
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationRespose> login(@Valid @RequestBody LoginRequest loginRequest) {
        AuthenticationRespose authResponse = authService.login(loginRequest);
        return ResponseEntity.ok(authResponse);
    }

    /**
     * Logout the currently authenticated user by removing their tokens from Redis.
     *
     * @return ResponseEntity with success message
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        authService.Logout();
        return ResponseEntity.ok("Successfully logged out");
    }

    /**
     * Refresh access token using a valid refresh token.
     *
     * @param request RefreshTokenRequest containing the refresh token
     * @return ResponseEntity with new AuthenticationRespose (new access token)
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        return authService.refreshToken(refreshToken);
    }
}
