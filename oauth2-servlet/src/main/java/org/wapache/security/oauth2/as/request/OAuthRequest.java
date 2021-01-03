/**
 *       Copyright 2010 Newcastle University
 *
 *          http://research.ncl.ac.uk/smart/
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wapache.security.oauth2.as.request;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import lombok.Getter;
import lombok.Setter;
import org.wapache.security.oauth2.common.OAuth;
import org.wapache.security.oauth2.common.exception.OAuthProblemException;
import org.wapache.security.oauth2.common.exception.OAuthSystemException;
import org.wapache.security.oauth2.common.utils.OAuthUtils;
import org.wapache.security.oauth2.common.validators.OAuthValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Abstract OAuth request for the Authorization server.
 */

@Getter
@Setter
public abstract class OAuthRequest {

    private Logger log = LoggerFactory.getLogger(OAuthRequest.class);

    HttpServletRequest request;

    protected OAuthValidator<HttpServletRequest> validator;
    // Map<grant_type, OAuthValidator>
    protected Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> validators = new HashMap<>();

    OAuthAuthzEntity authzEntity;

    public static OAuthAuthzEntity extract(HttpServletRequest request) {

        OAuthAuthzEntity authzEntity = new OAuthAuthzEntity();

        authzEntity.authorization = request.getHeader(OAuth.HeaderType.AUTHORIZATION);
        if(authzEntity.authorization!=null){
            authzEntity.decodedAuthorization = OAuthUtils.decodeClientAuthenticationHeader(authzEntity.authorization);
        }

        authzEntity.clientId = request.getParameter(OAuth.OAUTH_CLIENT_ID);
        authzEntity.clientSecret = request.getParameter(OAuth.OAUTH_CLIENT_SECRET);
        authzEntity.redirectUri = request.getParameter(OAuth.OAUTH_REDIRECT_URI);

        authzEntity.scope = request.getParameter(OAuth.OAUTH_SCOPE);
        authzEntity.scopes = OAuthUtils.decodeScopes(authzEntity.scope);

        return authzEntity;
    }

    public OAuthRequest(HttpServletRequest request) throws OAuthSystemException, OAuthProblemException {
        this.request = request;
        this.authzEntity = extract(request);
        validate();
    }

    protected void validate() throws OAuthSystemException, OAuthProblemException {
        try {
            validator = initValidator();
            validator.validateMethod(request);
            validator.validateContentType(request);
            validator.validateRequiredParameters(request);
            validator.validateClientAuthenticationCredentials(request);
        } catch (OAuthProblemException e) {
            try {
                String redirectUri = request.getParameter(OAuth.OAUTH_REDIRECT_URI);
                if (!OAuthUtils.isEmpty(redirectUri)) {
                    e.setRedirectUri(redirectUri);
                }
            } catch (Exception ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot read redirect_url from the request: {}", ex.getMessage());
                }
            }

            throw e;
        }

    }

    protected abstract OAuthValidator<HttpServletRequest> initValidator() throws OAuthProblemException, OAuthSystemException;

    public String getParam(String name){
        return request.getParameter(name);
    }

    public String getClientId() {
        String[] creds = authzEntity.getDecodedAuthorization();
        if (creds != null) {
            return creds[0];
        }
        return authzEntity.getClientId();
    }

    public String getRedirectURI() {
        return authzEntity.getRedirectUri();
    }

    public String getClientSecret() {
        String[] creds = authzEntity.getDecodedAuthorization();
        if (creds != null) {
            return creds[1];
        }
        return authzEntity.getClientSecret();
    }

    /**
     *
     * @return
     */
    public boolean isClientAuthHeaderUsed() {
        return authzEntity.getDecodedAuthorization() != null;
    }

    public Set<String> getScopes(){
        return authzEntity.getScopes();
    }

}
