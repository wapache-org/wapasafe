package org.wapache.security.oauth2.client.demo;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Oauth2ClientDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ClientDemoApplication.class);
    }


    @Bean
    public OpenAPI customOpenAPI(@Value("${springdoc.version}") String appVersion) {
        return new OpenAPI()
            .info(new Info()
                .title("Oauth2 Client API")
                .version(appVersion)
                .description("")
                .termsOfService("http://wapache.org/terms/")
                .license(new License().name("Apache 2.0").url("http://wapache.org"))
            );
    }

}
