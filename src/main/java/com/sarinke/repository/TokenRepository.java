package com.sarinke.repository;

import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Repository
@RequiredArgsConstructor
public class TokenRepository {

    private final RedisTemplate<String, String> redisTemplate;

    // ========================= REDIS KEY PREFIXES =========================

    private static final String ACCESS_PREFIX = "user:access:";
    private static final String REFRESH_PREFIX = "user:refresh:";
    private static final String ACCESS_BLACKLIST_PREFIX = "blacklist:access:";
    private static final String REFRESH_BLACKLIST_PREFIX = "blacklist:refresh:";

    @Value("${jwt.expiration}")
    private long accessTokenTtl;

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenTtl;

    // ========================= STORE TOKENS =========================
    public void storeTokens(
            String username,
            String accessToken,
            String refreshToken,
            String accessJti,
            String refreshJti
        ) {
            storeToken(ACCESS_PREFIX + username + ":" + accessJti, hash(accessToken), accessTokenTtl);
            storeToken(REFRESH_PREFIX + username + ":" + refreshJti, hash(refreshToken), refreshTokenTtl);
        }

    // ========================= BLACKLIST =========================

    public void blacklistAccessToken(String token) {
        blacklist(ACCESS_BLACKLIST_PREFIX + hash(token), accessTokenTtl);
    }

    public void blacklistRefreshToken(String token) {
        blacklist(REFRESH_BLACKLIST_PREFIX + hash(token), refreshTokenTtl);
    }

    public boolean isAccessTokenBlacklisted(String token) {
        return redisTemplate.hasKey(ACCESS_BLACKLIST_PREFIX + hash(token));
    }



    // ========================= REMOVE =========================

    public void removeSession(String username, String jti) {
        redisTemplate.delete(ACCESS_PREFIX + username + ":" + jti);
        redisTemplate.delete(REFRESH_PREFIX + username + ":" + jti);
    }

    // ========================= INTERNAL HELPERS =========================

    private void storeToken(String key, String value, long ttl) {
        redisTemplate.opsForValue().set(key, value, ttl, TimeUnit.MILLISECONDS);
    }

    private void blacklist(String key, long ttl) {
        redisTemplate.opsForValue().set(key, "blacklisted", ttl, TimeUnit.MILLISECONDS);
    }

    public String hash(String token) {
        return DigestUtils.sha256Hex(token);
    }
    public boolean isRefreshTokenBlacklisted(String refreshToken) {
        if (refreshToken == null) {
            return false;
        }
        String key = REFRESH_BLACKLIST_PREFIX + hash(refreshToken);
        return redisTemplate.hasKey(key);
    }

    public void removeAllTokens(String username) {
        // Pattern to find all access tokens for this user
        String accessPattern = ACCESS_PREFIX + username + ":*";
        String refreshPattern = REFRESH_PREFIX + username + ":*";

        // Find all matching access keys
        var accessKeys = redisTemplate.keys(accessPattern);
        if (accessKeys != null) {
            for (String key : accessKeys) {
                String token = redisTemplate.opsForValue().get(key);
                if (token != null) {
                    blacklist(ACCESS_BLACKLIST_PREFIX + token, accessTokenTtl);
                }
                redisTemplate.delete(key);
            }
        }

        // Find all matching refresh keys
        var refreshKeys = redisTemplate.keys(refreshPattern);
        if (refreshKeys != null) {
            for (String key : refreshKeys) {
                String token = redisTemplate.opsForValue().get(key);
                if (token != null) {
                    blacklist(REFRESH_BLACKLIST_PREFIX + token, refreshTokenTtl);
                }
                redisTemplate.delete(key);
            }
        }
    }

    /**
     * Retrieve all refresh tokens for a given user
     * Returns hashed tokens stored in Redis (never raw)
     */
    public Set<String> getRefreshTokens(String username) {
        String pattern = REFRESH_PREFIX + username + ":*";
        Set<String> keys = redisTemplate.keys(pattern);
        Set<String> tokens = new HashSet<>();

        if (keys != null) {
            for (String key : keys) {
                String token = redisTemplate.opsForValue().get(key);
                if (token != null) {
                    tokens.add(token);
                }
            }
        }

        return tokens;
    }

    /**
     * Retrieve all access tokens for a given user
     * Returns hashed tokens stored in Redis (never raw)
     */
    public Set<String> getAccessTokens(String username) {
        String pattern = ACCESS_PREFIX + username + ":*";
        Set<String> keys = redisTemplate.keys(pattern);
        Set<String> tokens = new HashSet<>();

        if (keys != null) {
            for (String key : keys) {
                String token = redisTemplate.opsForValue().get(key);
                if (token != null) {
                    tokens.add(token);
                }
            }
        }

        return tokens;
    }
    public String getAccessTokenByJti(String username, String jti) {
        String key = ACCESS_PREFIX + username + ":" + jti;
        return redisTemplate.opsForValue().get(key);
    }


}
