package org.wapache.security.oauth2.server.demo.web.filter;

import org.wapache.security.oauth2.server.demo.Constants;
import org.wapache.security.oauth2.server.demo.entity.Status;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.wapache.security.oauth2.common.OAuth;
import org.wapache.security.oauth2.common.error.OAuthError;
import org.wapache.security.oauth2.common.exception.OAuthProblemException;
import org.wapache.security.oauth2.common.exception.OAuthSystemException;
import org.wapache.security.oauth2.common.message.OAuthResponse;
import org.wapache.security.oauth2.common.message.types.ParameterStyle;
import org.wapache.security.oauth2.rs.request.OAuthAccessResourceRequest;
import org.wapache.security.oauth2.rs.response.OAuthRSResponse;
import org.springframework.http.HttpStatus;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

@WebFilter(urlPatterns = "/api/v1", filterName = "Oauth2Filter")
public class Oauth2Filter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        try {

            //构建OAuth资源请求
            // queryString方式获取参数
            OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request, ParameterStyle.QUERY);

            // 从Header请求头中获取参数
            // OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request, ParameterStyle.HEADER);

            String accessToken = oauthRequest.getAccessToken();

            // 验证Access Token
            if (!checkAccessToken(accessToken)) {
                // 如果不存在/过期了，返回未验证错误，需重新验证
                oAuthFaileResponse(res);
                return;
            }
            chain.doFilter(request, response);
        } catch (OAuthProblemException e) {
            try {
                oAuthFaileResponse(res);
            } catch (OAuthSystemException ex) {
                Logger.getLogger(getClass().getName()).log(Level.SEVERE, "error trying to access oauth server", ex);
            }
        } catch (OAuthSystemException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, "error trying to access oauth server", e);
        }
    }

    /**
     * oAuth认证失败时的输出
     *
     * @param res
     * @throws OAuthSystemException
     * @throws IOException
     */
    private void oAuthFaileResponse(HttpServletResponse res) throws OAuthSystemException, IOException {
        OAuthResponse oauthResponse = OAuthRSResponse
                .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setRealm(Constants.RESOURCE_SERVER_NAME)
                .setError(OAuthError.ResourceResponse.INVALID_TOKEN)
                .buildHeaderMessage();

        res.addHeader(OAuth.HeaderType.WWW_AUTHENTICATE, oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
        res.setContentType("application/json; charset=utf-8");
        res.setCharacterEncoding("utf-8");

        PrintWriter writer = res.getWriter();
        Gson gson = new GsonBuilder().create();
        writer.write(gson.toJson(getStatus(HttpStatus.UNAUTHORIZED.value(), Constants.INVALID_ACCESS_TOKEN)));
        writer.flush();
        writer.close();
    }

    /**
     * 验证accessToken
     *
     * @param accessToken
     * @return
     * @throws IOException
     */
    private boolean checkAccessToken(String accessToken) throws IOException {
        URL url = new URL(Constants.CHECK_ACCESS_CODE_URL + accessToken);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.disconnect();
        return HttpServletResponse.SC_OK == conn.getResponseCode();
    }

    private Status getStatus(int code, String msg) {
        Status status = new Status();
        status.setCode(code);
        status.setMsg(msg);
        return status;
    }

    @Override
    public void destroy() {

    }


}
