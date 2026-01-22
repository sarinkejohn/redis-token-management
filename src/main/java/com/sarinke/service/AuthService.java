package com.sarinke.service;

import com.sarinke.dto.AuthenticationRespose;
import com.sarinke.dto.LoginRequest;
import com.sarinke.dto.RegisterRequest;
import com.sarinke.dto.TokenPair;
import com.sarinke.model.User;
import com.sarinke.repository.TokenRepository;
import com.sarinke.repository.UserRepository;
import com.sarinke.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final CustomUserService customUserService;
    private final JwtTokenProvider tokenProvider;
    private final TokenRepository tokenRepository;

    public AuthenticationRespose registerNewUser(RegisterRequest request) {
        //check if user already exists
        userRepository.findByUsername(request.getUsername())
                .ifPresent(user -> {
                    throw new RuntimeException("User already exists!");
                });
        //create new user
        User user = new User(
                request.getUsername(),
                passwordEncoder.encode(request.getPassword())
        );
        userRepository.save(user);
        return authenticateUser(request.getUsername(), request.getPassword());
    }

    //User Login
    public AuthenticationRespose login(LoginRequest loginRequest) {
        return authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
    }

    /**
     * Authenticates a user, generates JWT tokens, stores them in Redis, and returns the Authentication response.
     *
     * @param username The username
     * @param password The password
     * @return AuthenticationRespose containing accessToken, refreshToken, and user authorities
     */
    private AuthenticationRespose authenticateUser(String username, String password) {
        // 1️⃣ Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // 2️⃣ Set authentication in SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3️⃣ Generate JWT Token pair (access + refresh)
        TokenPair tokenPair = tokenProvider.generateTokenPair(authentication);

        // 4️⃣ Store tokens in Redis
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 🔹 Recommended for multi-device:
        // tokenRepository.storeTokens(userDetails.getUsername(), tokenPair.getAccessToken(), tokenPair.getRefreshToken(),
        //        tokenPair.getAccessJti(), tokenPair.getRefreshJti());

        // Current single-device version:
        tokenRepository.storeTokens(
                userDetails.getUsername(),
                tokenPair.getAccessToken(),
                tokenPair.getRefreshToken(),
                tokenPair.getAccessJti(),
                tokenPair.getRefreshJti()
        );

        // Return Authentication response to client
        return new AuthenticationRespose(
                tokenPair.getAccessToken(),
                tokenPair.getRefreshToken(),
                userDetails.getAuthorities()
        );
    }


    public void Logout() {
        //get current authenticated User
        UserDetails userDetails = (UserDetails) SecurityContextHolder
                .getContext().getAuthentication().getPrincipal();
        //Remove all token for this user
        tokenRepository.removeAllTokens(userDetails.getUsername());
    }
    public ResponseEntity<?> refreshToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("ERROR: Invalid refresh token");
        }

        // 1️⃣ Verify refresh token scope
        var claims = tokenProvider.getClaimsFromToken(refreshToken);
        if (!"refresh".equals(claims.get("scopes"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("ERROR: Invalid refresh token");
        }

        // 2️⃣ Extract username and old JTI from refresh token
        String username = tokenProvider.getUsernameFromToken(refreshToken);
        String refreshJti = tokenProvider.getJtiFromToken(refreshToken); // old refresh JTI

        UserDetails userDetails = customUserService.loadUserByUsername(username);

        // 3️⃣ Generate a new access token
        String newAccessToken = tokenProvider.generateAccessToken(username);
        String accessJti = tokenProvider.getJtiFromToken(newAccessToken); // new access JTI

        // 4️⃣ Store the new access token with the old refresh token JTI
        tokenRepository.storeTokens(
                username,
                newAccessToken,
                refreshToken,
                accessJti,
                refreshJti
        );

        return ResponseEntity.ok(
                new AuthenticationRespose(newAccessToken, refreshToken, userDetails.getAuthorities())
        );
    }


}


