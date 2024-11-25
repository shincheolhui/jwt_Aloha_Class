package org.example.jwt.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.example.jwt.constants.SecurityConstants;
import org.example.jwt.domain.AuthenticationRequest;
import org.example.jwt.prop.JwtProp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@RestController
public class LoginController {

    @Autowired
    private JwtProp jwtProp;

    /**
     * /login
     * - username
     * - password
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest request) {

        String username = request.getUsername();
        String password = request.getPassword();
        log.info("username : {}", username);
        log.info("password : {}", password);

        // 임의로 사용자 권한 만듬
        List<String> roles = new ArrayList<>();
        roles.add("ROLE_USER");
        roles.add("ROLE_ADMIN");

        // 시크릿키 -> 바이트
        byte[] signingKeys = jwtProp.getSecretKey().getBytes();

        // 토큰 생성
        String jwt = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(signingKeys), Jwts.SIG.HS512)          // 시그니처에 사용할 비밀키, 알고리즘 설저
                .header().add("typ", SecurityConstants.TOKEN_TYPE)
                .and()
                .expiration(new Date(System.currentTimeMillis() + (1000*60*60*24*5)))  // 토큰 만료 시간 설정 (e.g., 5일)
                .claim("uid", username)                                             // payload - uid : "사용자 아이디"
                .claim("rol", roles)                                                // payload - role : [권한정보 배열]
                .compact();

        log.info("jwt : {}", jwt);

        return new ResponseEntity<String>(jwt, HttpStatus.OK);
    }

    // 토큰 해석
    @GetMapping("/user/info")
    public ResponseEntity<?> getUserInfo(@RequestHeader(name = "Authorization") String header) {

        log.info("header : {}", header);

        // Authorization : Bearer ${JWT}
        String jwt = header.replace(SecurityConstants.TOKEN_PREFIX, "");

        byte[] signingKeys = jwtProp.getSecretKey().getBytes();

        // 토큰 해석
        Jws<Claims> claimsJws = Jwts.parser()
                                    .verifyWith(Keys.hmacShaKeyFor(signingKeys))
                                    .build()
                                    .parseSignedClaims(jwt);
        log.info("claimsJws : {}", claimsJws);

        Claims payload = claimsJws.getPayload();
        // uid : user
        String username = payload.get("uid").toString();
        log.info("username : {}", username);
        // rol : [ROLE_USER, ROLE_ADMIN]
        Object rol = payload.get("rol");
        log.info("rol : {}", rol);

        return new ResponseEntity<>(claimsJws, HttpStatus.OK);
    }
}
