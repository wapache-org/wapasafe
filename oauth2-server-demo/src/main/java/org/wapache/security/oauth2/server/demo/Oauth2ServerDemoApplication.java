package org.wapache.security.oauth2.server.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@EnableCaching
@SpringBootApplication
public class Oauth2ServerDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ServerDemoApplication.class);
    }

}
