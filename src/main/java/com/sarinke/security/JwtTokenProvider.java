package com.sarinke.security;

import com.sarinke.dto.TokenPair;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    // ========================= TOKEN GENERATION =========================

    public TokenPair generateTokenPair(Authentication authentication) {
        // Generate JTIs
        String accessJti = UUID.randomUUID().toString();
        String refreshJti = UUID.randomUUID().toString();

        UserDetails user = (UserDetails) authentication.getPrincipal();

        // Generate tokens with the helper method that accepts jti
        String accessToken = generateToken(user.getUsername(), jwtExpirationMs, null, accessJti);

        Map<String, Object> refreshClaims = new HashMap<>();
        refreshClaims.put("scopes", "refresh");
        String refreshToken = generateToken(user.getUsername(), refreshTokenExpirationMs, refreshClaims, refreshJti);

        // Return token pair with JTIs for Redis storage
        return new TokenPair(accessToken, refreshToken, accessJti, refreshJti);
    }


    public String generateAccessToken(String username) {
        String accessJti = UUID.randomUUID().toString();
        return generateToken(username, jwtExpirationMs, null, accessJti);
    }

    private String generateRefreshToken(String username) {
        String refreshJti = UUID.randomUUID().toString();
        Map<String, Object> claims = new HashMap<>();
        claims.put("scopes", "refresh");
        return generateToken(username, refreshTokenExpirationMs, claims, refreshJti);
    }

    /**
     * Generate a JWT token for a user with optional claims and given JTI
     *
     * @param username Username
     * @param expiration Expiration in ms
     * @param claims Optional claims (e.g., refresh scope)
     * @param jti Unique token ID
     * @return JWT string
     */
    private String generateToken(String username, long expiration, Map<String, Object> claims, String jti) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        JwtBuilder builder = Jwts.builder()
                .id(jti) // use provided JTI
                .issuer(issuer)
                .subject(username)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey());

        if (claims != null) {
            builder.claims(claims);
        }

        return builder.compact();
    }


    // ========================= TOKEN PARSING =========================

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public String getJtiFromToken(String token) {
        return getClaimsFromToken(token).getId();
    }

    public boolean validateToken(String token) {
        try {
            getClaimsFromToken(token);
            return true;
        } catch (Exception ex) {
            log.warn("Invalid JWT token");
            return false;
        }
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }


}
