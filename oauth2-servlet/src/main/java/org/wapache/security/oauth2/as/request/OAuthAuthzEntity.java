package org.wapache.security.oauth2.as.request;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class OAuthAuthzEntity {

    String clientId;
    String clientSecret;
    String redirectUri;

    String scope;
    Set<String> scopes;

    String authorization;
    String[] decodedAuthorization;

}
