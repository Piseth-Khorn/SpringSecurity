package com.allweb.SpringSecurity.controller;

import com.allweb.SpringSecurity.exception.UserNotFoundException;
import com.allweb.SpringSecurity.model.UserModel;
import com.allweb.SpringSecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("api/v1/user")
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }
    @GetMapping
    @PreAuthorize("hasAnyAuthority('student:read')")
    public ResponseEntity<List<UserModel>> getAllUser(){
        return new ResponseEntity<>(userService.getAllUser(), HttpStatus.ACCEPTED);
    }
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRAINEE')")
    public ResponseEntity<?> getUserById(@PathVariable("id") UUID uuid){
        UserModel userModel = userService.getUserById(uuid).orElseThrow(() -> new UserNotFoundException("User Id not found " + uuid.toString()));
        return new ResponseEntity<>(userModel,HttpStatus.ACCEPTED);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRAINEE')")
    public ResponseEntity<UserModel>save(@RequestBody UserModel userModel) {
        userModel.setPassword(passwordEncoder.encode(userModel.getPassword()));
        UserModel save = userService.save(userModel);
        return new ResponseEntity<>(save,HttpStatus.CREATED);
    }
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ADMINTRAINEE')")
    public ResponseEntity<?>deleteUser(@PathVariable("id") UUID id){
        userService.delete(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }



}
