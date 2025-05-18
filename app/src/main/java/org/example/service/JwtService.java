package org.example.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    public static final String SECRET = "fda2169ad7f7c53e1ef1eddd5ee2200fea6dc67f2beb0d923a022636254266ef5f5b2ab1c3c2e2b71d28633032773da5528c83ba21f0fd6913542ab66159b12c795e419e6b3962b2593530f0ac294f016c6be94f8f38ee1c187a14667e6d83b8e6b11a1735352f8432866f8411ae752a31716f63844b74586056f00e5cb863e5256acef893f524ad5c3abc42fc9af01247fd18609ca33c7a3cf62d80120e4829ebe309a2093f3d32d1b4b6208118275ad125c1d8db174d0a450fde9457c12711940ea451d8e4738bc4731373506efa0ce1b710546cef0498168372946bb1dc2b40bdb4b8579b2a68205f51696f4572a9318da96813d4767e85ce6e66e2b0c16a";
    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public Date extractExpiration(String token){
        return extractClaims(token, Claims::getExpiration);
    }

    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private String createToken(Map<String, Object> claims, String username){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*1))
                .signWith(getSignKey(), SignatureAlgorithm.HS384).compact();
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
