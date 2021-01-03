package org.wapache.security.oauth2.server.demo.web.controller.oauth;

import org.wapache.security.oauth2.server.demo.Constants;
import org.wapache.security.oauth2.server.demo.entity.Status;
import org.wapache.security.oauth2.server.demo.entity.User;
import org.wapache.security.oauth2.server.demo.service.OAuthService;
import org.wapache.security.oauth2.server.demo.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.wapache.security.oauth2.common.OAuth;
import org.wapache.security.oauth2.common.error.OAuthError;
import org.wapache.security.oauth2.common.exception.OAuthProblemException;
import org.wapache.security.oauth2.common.exception.OAuthSystemException;
import org.wapache.security.oauth2.common.message.OAuthResponse;
import org.wapache.security.oauth2.common.message.types.ParameterStyle;
import org.wapache.security.oauth2.common.utils.OAuthUtils;
import org.wapache.security.oauth2.rs.request.OAuthAccessResourceRequest;
import org.wapache.security.oauth2.rs.response.OAuthRSResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 在 OAuth2 的概念里，所有的接口都被称为资源，接口的权限也就是资源的权限
 */
@RestController
@Tag(name = "OAuth2")
public class UserResourceController {

    @Autowired
    private OAuthService oAuthService;

    @Autowired
    private UserService userService;

    @GetMapping("/resource")
    @Operation(
        summary = "获取用户资源",
        description = "此接口用于演示访问令牌的校验, accessToken支持通过HTTP头("+OAuth.HeaderType.AUTHORIZATION+")或者查询参数("+OAuth.OAUTH_BEARER_TOKEN+"或"+OAuth.OAUTH_TOKEN+")方式传递。",
        parameters = {
            @Parameter(in = ParameterIn.HEADER, name = OAuth.HeaderType.AUTHORIZATION, schema = @Schema(implementation = String.class)),
            @Parameter(in = ParameterIn.QUERY, name = OAuth.OAUTH_BEARER_TOKEN, schema = @Schema(implementation = String.class)),
            @Parameter(in = ParameterIn.QUERY, name = OAuth.OAUTH_TOKEN, schema = @Schema(implementation = String.class))
        }
    )
    public ResponseEntity<Object> userInfo(
        @RequestParam(defaultValue = "true") Boolean checkAccessToken, HttpServletRequest request
    ) throws OAuthSystemException {
        try {
            //构建OAuth资源请求
            OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest(request,
                ParameterStyle.HEADER, ParameterStyle.QUERY
            );

            //获取Access Token
            String accessToken = oauthRequest.getAccessToken();

            //验证Access Token
            if (checkAccessToken && !oAuthService.checkAccessToken(accessToken)) {
                HttpHeaders responseHeaders = new HttpHeaders();{

                    responseHeaders.add("Content-Type", "application/json; charset=utf-8");

                    // 如果不存在/过期了，返回未验证错误，需重新验证
                    OAuthResponse oauthResponse = OAuthRSResponse
                        .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setRealm(Constants.RESOURCE_SERVER_NAME)
                        .setError(OAuthError.ResourceResponse.INVALID_TOKEN)
                        .buildHeaderMessage();

                }

                Status status = new Status();
                status.setCode(HttpStatus.UNAUTHORIZED.value());
                status.setMsg(Constants.INVALID_ACCESS_TOKEN);

                return new ResponseEntity<>(status, responseHeaders, HttpStatus.UNAUTHORIZED);
            }

            //获取用户名
            String username = oAuthService.getUsernameByAccessToken(accessToken);
            User user = userService.findByUsername(username);

            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (OAuthProblemException e) {
            //检查是否设置了错误码
            String errorCode = e.getError();

            if (OAuthUtils.isEmpty(errorCode)) {
                HttpHeaders headers = new HttpHeaders();{
                    OAuthResponse oauthResponse = OAuthRSResponse
                        .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setRealm(Constants.RESOURCE_SERVER_NAME)
                        .buildHeaderMessage();
                    headers.add(OAuth.HeaderType.WWW_AUTHENTICATE, oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
                }
                return new ResponseEntity<>(headers, HttpStatus.UNAUTHORIZED);
            }else{
                HttpHeaders headers = new HttpHeaders();{
                    OAuthResponse oauthResponse = OAuthRSResponse
                        .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setRealm(Constants.RESOURCE_SERVER_NAME)
                        .setError(e.getError())
                        .setErrorDescription(e.getDescription())
                        .setErrorUri(e.getUri())
                        .buildHeaderMessage();
                    headers.add(OAuth.HeaderType.WWW_AUTHENTICATE, oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
                }
                return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
            }
        }
    }
}