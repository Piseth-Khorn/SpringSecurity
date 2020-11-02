package com.allweb.SpringSecurity.service;

import com.allweb.SpringSecurity.model.UserModel;
import com.allweb.SpringSecurity.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<UserModel> getUserName(String name){ return userRepository.getUserModelByName(name);}

    public Optional<UserModel> getUserEmail(String email){ return userRepository.getUserModelByEmail(email);}

    public List<UserModel> getAllUser(){
        return userRepository.findAll();
    }

    public Optional<UserModel> getUserById(UUID id){
        return userRepository.findById(id);
    }

    public UserModel save(UserModel userModel){
        return userRepository.save(userModel);
    }

    public UserModel update(UserModel userModel){
        return userRepository.save(userModel);
    }

    public void delete(UUID id){
        userRepository.deleteById(id);
    }

}
