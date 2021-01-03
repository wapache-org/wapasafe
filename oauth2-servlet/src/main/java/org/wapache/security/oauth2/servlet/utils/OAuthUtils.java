package org.wapache.security.oauth2.servlet.utils;

import javax.servlet.http.HttpServletRequest;

// org.apache.oltu.oauth2.common.utils.OAuthUtils

public class OAuthUtils {

    public static final String MULTIPART = "multipart/";

    public static boolean isMultipart(HttpServletRequest request) {

        if (!"post".equals(request.getMethod().toLowerCase())) {
            return false;
        }
        String contentType = request.getContentType();
        if (contentType == null) {
            return false;
        }
        if (contentType.toLowerCase().startsWith(MULTIPART)) {
            return true;
        }
        return false;
    }

}
