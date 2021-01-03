package org.wapache.security.oauth2.server.demo.web.controller.oauth;

import org.wapache.security.oauth2.server.demo.Constants;
import org.wapache.security.oauth2.server.demo.service.OAuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.wapache.security.oauth2.as.issuer.MD5Generator;
import org.wapache.security.oauth2.as.issuer.OAuthIssuer;
import org.wapache.security.oauth2.as.issuer.OAuthIssuerImpl;
import org.wapache.security.oauth2.as.request.OAuthTokenRequest;
import org.wapache.security.oauth2.as.response.OAuthASResponse;
import org.wapache.security.oauth2.common.OAuth;
import org.wapache.security.oauth2.common.error.OAuthError;
import org.wapache.security.oauth2.common.exception.OAuthProblemException;
import org.wapache.security.oauth2.common.exception.OAuthSystemException;
import org.wapache.security.oauth2.common.message.OAuthResponse;
import org.wapache.security.oauth2.common.message.types.GrantType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URISyntaxException;

@RestController
@Tag(name = "OAuth2")
public class AccessTokenController {

    @Autowired
    private OAuthService oAuthService;

    /**
     * 获取令牌
     * @param request
     * @return
     * @throws URISyntaxException
     * @throws OAuthSystemException
     */
    @RequestMapping(value = "/accessToken", method = RequestMethod.POST)
    public ResponseEntity<Object> token(HttpServletRequest request) throws URISyntaxException, OAuthSystemException {

        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type","application/json; charset=utf-8");

        try {

            //构建OAuth请求
            OAuthTokenRequest oauthRequest = new OAuthTokenRequest(request);

            //检查提交的客户端id是否正确
            if (!oAuthService.checkClientId(oauthRequest.getClientId())) {
                OAuthResponse response = OAuthASResponse
                    .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(OAuthError.TokenResponse.INVALID_CLIENT)
                    .setErrorDescription(Constants.INVALID_CLIENT_ID)
                    .buildJSONMessage();
                return new ResponseEntity<>(response.getBody(), headers, HttpStatus.valueOf(response.getResponseStatus()));
            }

            // 检查客户端安全KEY是否正确
            if (!oAuthService.checkClientSecret(oauthRequest.getClientSecret())) {
                OAuthResponse response = OAuthASResponse
                    .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                    .setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT)
                    .setErrorDescription(Constants.INVALID_CLIENT_ID)
                    .buildJSONMessage();
                return new ResponseEntity<>(response.getBody(), headers, HttpStatus.valueOf(response.getResponseStatus()));
            }

            String authCode = oauthRequest.getParam(OAuth.OAUTH_CODE);
            // 检查验证类型，此处只检查AUTHORIZATION_CODE类型，其他的还有PASSWORD或REFRESH_TOKEN
            if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(GrantType.AUTHORIZATION_CODE.toString())) {
                if (!oAuthService.checkAuthCode(authCode)) {
                    OAuthResponse response = OAuthASResponse
                            .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                            .setError(OAuthError.TokenResponse.INVALID_GRANT)
                            .setErrorDescription(Constants.INVALID_AUTH_CODE)
                            .buildJSONMessage();
                    return new ResponseEntity<>(response.getBody(), headers, HttpStatus.valueOf(response.getResponseStatus()));
                }
            }else{
                OAuthResponse response = OAuthASResponse
                    .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                    .setError(OAuthError.TokenResponse.INVALID_GRANT)
                    .setErrorDescription(Constants.INVALID_AUTH_CODE)
                    .buildJSONMessage();
                return new ResponseEntity<>(response.getBody(), headers, HttpStatus.valueOf(response.getResponseStatus()));
            }

            //生成Access Token
            OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
            final String accessToken = oauthIssuerImpl.accessToken();
            oAuthService.addAccessToken(accessToken, oAuthService.getUsernameByAuthCode(authCode));

            //生成OAuth响应
            OAuthResponse response = OAuthASResponse
                    .tokenResponse(HttpServletResponse.SC_OK)
                    .setAccessToken(accessToken)
                    .setExpiresIn(String.valueOf(oAuthService.getExpireIn()))
                    .buildJSONMessage();

            //根据OAuthResponse生成ResponseEntity
            return new ResponseEntity<>(response.getBody(), headers, HttpStatus.valueOf(response.getResponseStatus()));

        } catch (OAuthProblemException e) {
            //构建错误响应
            OAuthResponse res = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(e).buildJSONMessage();
            return new ResponseEntity<>(res.getBody(), headers, HttpStatus.valueOf(res.getResponseStatus()));
        }
    }

    /**
     * 验证accessToken
     *
     * 当后台第三方服务接收到来自客户端(浏览器/APP)的请求后，需要拿着请求中的 token 到认证服务端做 token 验证，就是请求的这个接口
     *
     * @param accessToken
     * @return
     */
    @RequestMapping(value = "/accessToken/check", method = RequestMethod.GET)
    public ResponseEntity<Object> checkAccessToken(@RequestParam("access_token") String accessToken) {
        return oAuthService.checkAccessToken(accessToken)
        ? new ResponseEntity<>(HttpStatus.valueOf(HttpServletResponse.SC_OK))
        : new ResponseEntity<>(HttpStatus.valueOf(HttpServletResponse.SC_UNAUTHORIZED))
        ;
    }

}
