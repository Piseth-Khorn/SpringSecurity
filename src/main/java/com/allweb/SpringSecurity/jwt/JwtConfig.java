package com.allweb.SpringSecurity.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {
    private String secretkey;
    private String tokenPrefix;
    private Integer tokenExprirationAfterDays;
    public JwtConfig(){}

    public String getSecretkey() {
        return secretkey;
    }

    public void setSecretkey(String secretkey) {
        this.secretkey = secretkey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExprirationAfterDays() {
        return tokenExprirationAfterDays;
    }

    public void setTokenExprirationAfterDays(Integer tokenExprirationAfterDays) {
        this.tokenExprirationAfterDays = tokenExprirationAfterDays;
    }
    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }

}
