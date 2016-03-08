package ameba.security.shiro.util;

import ameba.core.Requests;
import ameba.http.session.Session;

/**
 * @author icode
 */
public class WebUtil {
    private WebUtil() {
    }

    public static boolean isHttp() {
        return Requests.getRequest() != null;
    }

    public static boolean hasSession() {
        return Session.get(false) != null;
    }
}
