package com.example.vahak.apigatewayservice.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String SECRET;

    @Value("${jwt.expiry}")
    private int expiry;

    public String createToken(Map<String, Object> payload, String email){
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiry*1000L);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .claims(payload)
                .subject(email)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public String createToken(String email){
        return createToken(new HashMap<>(), email);
    }

    public SecretKey getSignKey(){
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public Claims extractAllPayloads(String token){
        return Jwts
                .parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllPayloads(token);
        return claimsResolver.apply(claims);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractEmail(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Object extractAnyPayload(String token, String payloadKey){
        Claims claim = extractAllPayloads(token);
        return claim.get(payloadKey);
    }

    public String extractPhoneNumber(String token){
        Claims claim = extractAllPayloads(token);
        return (String)claim.get("phoneNumber");
    }

    public Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, String email){
        final String userEmailFromToken = extractEmail(token);
        return (userEmailFromToken.equals(email) && !isTokenExpired(token));
    }

    public Boolean validateToken2(String token) {
        try {
            extractAllPayloads(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }
}
