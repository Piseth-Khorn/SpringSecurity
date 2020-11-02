package com.allweb.SpringSecurity.auth;

import com.allweb.SpringSecurity.exception.UserNotFoundException;
import com.allweb.SpringSecurity.model.UserModel;
import com.allweb.SpringSecurity.service.UserService;
import com.google.common.collect.Lists;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.allweb.SpringSecurity.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder, UserService userService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers(username)
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(String userNameOrEmail) {
        //UserModel userModel = userService.getUserName(username).orElseThrow(() -> new UserNotFoundException("Username not found " + username));

        UserModel userModel = null;
        String emailOrUsername = null;

            if (userService.getUserName(userNameOrEmail).isPresent()) {
                userModel = userService.getUserName(userNameOrEmail).get();
                emailOrUsername = userModel.getName();
            } else if (userService.getUserEmail(userNameOrEmail).isPresent()) {
                userModel = userService.getUserEmail(userNameOrEmail).get();
                emailOrUsername = userModel.getEmail();
            }else
                throw new UserNotFoundException("Username or Email not found " + userNameOrEmail);


        Set<SimpleGrantedAuthority> grantedAuthorities = null;

        assert userModel != null;
        if (userModel.getRole().toUpperCase().equals("ADMIN"))
            grantedAuthorities = ADMIN.getGrantedAuthorities();
        else if (userModel.getRole().toUpperCase().equals("ADMINTRAINEE"))
            grantedAuthorities = ADMINTRAINEE.getGrantedAuthorities();
        else
            grantedAuthorities = STUDENT.getGrantedAuthorities();

        return Lists.newArrayList(
                new ApplicationUser(
                        emailOrUsername,
                        userModel.getPassword(),
                        grantedAuthorities,
                        true,
                        true,
                        true,
                        true
                )
        );

//        return Lists.newArrayList(
//                new ApplicationUser(
//                        userModel.getName(),
//                        userModel.getPassword(),
//                        STUDENT.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true),
//                new ApplicationUser(
//                        "piseth",
//                        passwordEncoder.encode("piseth123"),
//                        ADMIN.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true),
//                new ApplicationUser(
//                        "tome",
//                        passwordEncoder.encode("tome123"),
//                        ADMINTRAINEE.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true)
//
//
//        );

    }
}
