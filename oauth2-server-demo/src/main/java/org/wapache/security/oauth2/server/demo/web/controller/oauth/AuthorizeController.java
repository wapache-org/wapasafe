package org.wapache.security.oauth2.server.demo.web.controller.oauth;

import org.wapache.security.oauth2.server.demo.Constants;
import org.wapache.security.oauth2.server.demo.entity.Client;
import org.wapache.security.oauth2.server.demo.entity.Status;
import org.wapache.security.oauth2.server.demo.security.SecurityUserDetails;
import org.wapache.security.oauth2.server.demo.service.ClientService;
import org.wapache.security.oauth2.server.demo.service.OAuthService;
import org.wapache.security.oauth2.server.demo.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.wapache.security.oauth2.as.issuer.MD5Generator;
import org.wapache.security.oauth2.as.issuer.OAuthIssuerImpl;
import org.wapache.security.oauth2.as.request.OAuthAuthzEntity;
import org.wapache.security.oauth2.as.request.OAuthAuthzRequest;
import org.wapache.security.oauth2.as.response.OAuthASResponse;
import org.wapache.security.oauth2.common.OAuth;
import org.wapache.security.oauth2.common.error.OAuthError;
import org.wapache.security.oauth2.common.exception.OAuthProblemException;
import org.wapache.security.oauth2.common.exception.OAuthSystemException;
import org.wapache.security.oauth2.common.message.OAuthResponse;
import org.wapache.security.oauth2.common.message.types.ResponseType;
import org.wapache.security.oauth2.common.utils.OAuthUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;

@Controller
@Tag(name = "OAuth2")
public class AuthorizeController {

    @Autowired
    private OAuthService oAuthService;
    @Autowired
    private ClientService clientService;
    @Autowired
    private UserService userService;

    // https://learn.fotoware.com/Integrations_and_APIs/Authorizing_applications_using_OAuth/06_Handling_OAuth_2.0_Errors
    // https://learn.fotoware.com/Integrations_and_APIs/Authorizing_applications_using_OAuth/06_Handling_OAuth_2.0_Errors/OAuth_2.0_Error_Reference

    /**
     * 第三方应用 申请 用户授权。
     *
     * @param model
     * @param request
     * @return
     * @throws URISyntaxException
     * @throws OAuthSystemException
     */
    @RequestMapping(value = "/authorize", method = RequestMethod.POST)
    public Object request(Model model, HttpServletRequest request, Principal principal) throws URISyntaxException, OAuthSystemException {

        HttpSession session = request.getSession(true);
        try {
            // 构建OAuth 授权请求
            OAuthAuthzRequest oauthRequest = new OAuthAuthzRequest(request);

            String callback = oauthRequest.getRedirectURI();
            String prefix = callback.contains("?") ? "&" : "?";

            // responseType目前仅支持CODE，另外还有TOKEN
            String responseType = oauthRequest.getParam(OAuth.OAUTH_RESPONSE_TYPE);
            if (!responseType.equals(ResponseType.CODE.toString())) {
                return redirectToCallbackError(oauthRequest, OAuthError.TokenResponse.INVALID_GRANT, "responseType目前仅支持CODE");
            }

            // 检查传入的客户端id是否正确
            if (!oAuthService.checkClientId(oauthRequest.getClientId())) {
                return redirectToCallbackError(oauthRequest, OAuthError.TokenResponse.INVALID_CLIENT, Constants.INVALID_CLIENT_ID);
            }

            // TODO 其他检查暂略

            SecurityUserDetails userDetails = null;
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (!(auth instanceof AnonymousAuthenticationToken)) {
                // userDetails = auth.getPrincipal()
                userDetails = (SecurityUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            }

            //
            Client client = clientService.findByClientId(oauthRequest.getClientId());

            model.addAttribute("client", client);
            model.addAttribute("user", userDetails==null? null : userDetails.getUser());
            model.addAttribute("authRequest", oauthRequest.getAuthzEntity());

            // TODO 应该保存在某个地方, 区分client_id, 暂时先保存在session吧
            session.setAttribute("authRequest", oauthRequest.getAuthzEntity());

        } catch (OAuthProblemException e) {

            // 告诉客户端没有传入redirectUri
            String redirectUri = e.getRedirectUri();
            if (OAuthUtils.isEmpty(redirectUri)) {
                Status status = new Status();
                status.setCode(HttpStatus.NOT_FOUND.value());
                status.setMsg(Constants.INVALID_REDIRECT_URI);
                model.addAttribute("error", status);
            }else{
                return redirectToCallbackError(e);
            }
        }

        return "authorize"; // 跳转到授权界面

    }

    /**
     * 用户确认授权。
     *
     * @param model
     * @param request
     * @return
     * @throws URISyntaxException
     * @throws OAuthSystemException
     */
    @RequestMapping(value = "/authorize/confirm", method = RequestMethod.POST)
    public Object confirm(String scope, Model model, HttpServletRequest request) throws URISyntaxException, OAuthSystemException {

        // TODO session, authzEntity, userDetails的判空， 暂时没做
        HttpSession session = request.getSession(false);
        OAuthAuthzEntity authzEntity = session==null ? null : (OAuthAuthzEntity)session.getAttribute("authRequest");
        SecurityUserDetails userDetails = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof AnonymousAuthenticationToken)) {
            // userDetails = auth.getPrincipal()
            userDetails = (SecurityUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        }

        if(authzEntity==null){
            Status status = new Status();
            status.setCode(HttpStatus.BAD_REQUEST.value());
            status.setMsg("授权请求已过期，请重新发起授权！");
            model.addAttribute("error", status);
            return "authorize"; // 跳转到授权界面
        }else if(userDetails==null){
            Status status = new Status();
            status.setCode(HttpStatus.BAD_REQUEST.value());
            status.setMsg("会话已过期，请重新登录！");
            model.addAttribute("error", status);
            return "authorize"; // 跳转到授权界面
        }else if(StringUtils.isEmpty(scope)){
            return redirectToCallbackError(
                authzEntity.getRedirectUri(),
                OAuthError.ResourceResponse.INSUFFICIENT_SCOPE,
                "用户没有同意授权！"
            );
        }


        // 生成授权码
        OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
        String authorizationCode = oauthIssuerImpl.authorizationCode();

        // 保存授权码
        oAuthService.addAuthCode(authorizationCode, userDetails.getUsername());

        // 重定向到回调地址
        return redirectToCallback(request, authzEntity.getRedirectUri(), authorizationCode);
    }

    private Object redirectToCallback( HttpServletRequest request, String location, String authorizationCode) throws OAuthSystemException, URISyntaxException {
        // 构建OAuth响应
        final OAuthResponse response = OAuthASResponse.authorizationResponse(request, HttpServletResponse.SC_FOUND)
            .setCode(authorizationCode) // 设置授权码
            .location(location) // 得到客户端重定向地址
            .buildQueryMessage();

        // 重定向到回调地址
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(response.getLocationUri()));
        return new ResponseEntity<>(headers, HttpStatus.valueOf(response.getResponseStatus()));
    }

    private Object redirectToCallbackError(OAuthProblemException e) throws OAuthSystemException, URISyntaxException {
        final OAuthResponse response = OAuthASResponse.errorResponse(e).buildQueryMessage();
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(response.getLocationUri()));
        return new ResponseEntity<>(headers, HttpStatus.valueOf(response.getResponseStatus()));
    }

    private Object redirectToCallbackError(OAuthAuthzRequest request, String error, String description) throws OAuthSystemException, URISyntaxException {
        return redirectToCallbackError(request.getRedirectURI(), error, description);
    }

    private Object redirectToCallbackError(String location, String error, String description) throws OAuthSystemException, URISyntaxException {
        final OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
            .location(location)
            .setError(error)
            .setErrorDescription(description)
            .buildQueryMessage();
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(response.getLocationUri()));
        return new ResponseEntity<>(headers, HttpStatus.valueOf(response.getResponseStatus()));
    }

//    private boolean login(HttpServletRequest request) {
//        if (OAuth.HttpMethod.GET.equalsIgnoreCase(request.getMethod())) {
//            request.setAttribute("error", "非法的请求");
//            return false;
//        }
//
//        String username = request.getParameter("username");
//        String password = request.getParameter("password");
//
//        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
//            request.setAttribute("error", "登录失败:用户名或密码不能为空");
//            return false;
//        }
//
//        try {
//            // 写登录逻辑
//            User user = userService.findByUsername(username);
//            if (user != null) {
//                if (!userService.checkUser(username, password, user.getSalt(), user.getPassword())) {
//                    request.setAttribute("error", "登录失败:密码不正确");
//                    return false;
//                } else {
//                    return true;
//                }
//            } else {
//                request.setAttribute("error", "登录失败:用户名不正确");
//                return false;
//            }
//        } catch (Exception e) {
//            request.setAttribute("error", "登录失败:" + e.getClass().getName());
//            return false;
//        }
//    }

}