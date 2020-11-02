package com.allweb.SpringSecurity.auth;

import com.allweb.SpringSecurity.jwt.JwtUtils;
import com.allweb.SpringSecurity.model.UserModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("api/auth")
public class AuthController {


    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final SecretKey secretKey;
    private final JwtUtils JwtUtils;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, SecretKey secretKey, com.allweb.SpringSecurity.jwt.JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.secretKey = secretKey;
        JwtUtils = jwtUtils;
    }

    @PostMapping
    public ResponseEntity<?> authenticateUser(@RequestBody UserModel user) {
        System.out.println(user.toString());
        Map<String, String> map = new HashMap<>();
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getName(), user.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = JwtUtils.generateJwtToken(authentication);
        map.put("Authorization", token);
        return new ResponseEntity<>(map, HttpStatus.OK);
    }

}
