package ameba.security.shiro.internal.mgt;

import ameba.core.Requests;
import ameba.util.Cookies;
import ameba.util.Times;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import java.util.Date;

/**
 * @author icode
 */
public class CookieRememberMeManager extends AbstractRememberMeManager {
    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "r";
    public static final String REQ_KEY_PRE = CookieRememberMeManager.class.getName() + ".";
    public static final String RM_REMEMBER_COOKIE_KEY = REQ_KEY_PRE + "removeRememberMe";
    public static final String ADD_REMEMBER_COOKIE_KEY = REQ_KEY_PRE + "addRememberMe";
    public static final int COOKIE_MAX_AGE = Times.parseDuration("7d");
    private static final Logger logger = LoggerFactory.getLogger(CookieRememberMeManager.class);
    private NewCookie cookie;

    public NewCookie getCookie() {
        if (cookie == null) {
            this.cookie = new NowCookie(
                    DEFAULT_REMEMBER_ME_COOKIE_NAME,
                    null,
                    "/",
                    null,
                    NowCookie.DEFAULT_VERSION,
                    null,
                    COOKIE_MAX_AGE,
                    null,
                    true);
        }
        return cookie;
    }

    public void setCookie(NewCookie cookie) {
        this.cookie = cookie;
    }

    @Override
    protected void forgetIdentity(Subject subject) {
        forgetIdentity();
    }

    private void forgetIdentity() {
        Requests.setProperty(RM_REMEMBER_COOKIE_KEY, this.cookie.getName());
    }

    @Override
    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        String base64 = Base64.encodeToString(serialized);
        NewCookie template = getCookie(); //the class attribute is really a template for the outgoing cookies
        NewCookie cookie = new NewCookie(
                template.getName(),
                base64,
                template.getPath(),
                template.getDomain(),
                template.getVersion(),
                template.getComment(),
                template.getMaxAge(),
                template.getExpiry(),
                template.isSecure(),
                template.isHttpOnly());
        Requests.removeProperty(RM_REMEMBER_COOKIE_KEY);
        Requests.setProperty(ADD_REMEMBER_COOKIE_KEY, cookie);
    }

    @Override
    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
        if (isIdentityRemoved()) {
            return null;
        }

        Cookie cookie = Requests.getCookies().get(getCookie().getName());
        //no cookie set - new site visitor?
        if (cookie == null) return null;
        String base64 = cookie.getValue();
        if (Cookies.DELETED_COOKIE_VALUE.equals(base64)) return null;

        if (base64 != null) {
            base64 = ensurePadding(base64);
            logger.trace("Acquired Base64 encoded identity [" + base64 + "]");
            byte[] decoded = Base64.decode(base64);
            logger.trace("Base64 decoded byte array length: " + (decoded != null ? decoded.length : 0) + " bytes.");
            return decoded;
        } else {
            //no cookie set - new site visitor?
            return null;
        }
    }

    private boolean isIdentityRemoved() {
        return Requests.getProperty(RM_REMEMBER_COOKIE_KEY) != null;
    }

    @Override
    public void forgetIdentity(SubjectContext subjectContext) {
        forgetIdentity();
    }

    /**
     * Sometimes a user agent will send the rememberMe cookie value without padding,
     * most likely because {@code =} is a separator in the cookie header.
     * <p/>
     * Contributed by Luis Arias.  Thanks Luis!
     *
     * @param base64 the base64 encoded String that may need to be padded
     * @return the base64 String padded if necessary.
     */
    private String ensurePadding(String base64) {
        int length = base64.length();
        if (length % 4 != 0) {
            StringBuilder sb = new StringBuilder(base64);
            for (int i = 0; i < length % 4; ++i) {
                sb.append('=');
            }
            base64 = sb.toString();
        }
        return base64;
    }

    private static class NowCookie extends NewCookie {

        public NowCookie(String name, String value) {
            super(name, value);
        }

        public NowCookie(String name, String value, String path, String domain, String comment, int maxAge) {
            super(name, value, path, domain, comment, maxAge, false);
        }

        public NowCookie(String name, String value, String path, String domain, String comment, int maxAge, boolean httpOnly) {
            super(name, value, path, domain, comment, maxAge, false, httpOnly);
        }

        public NowCookie(String name, String value, String path, String domain, int version, String comment, int maxAge) {
            super(name, value, path, domain, version, comment, maxAge, false);
        }

        public NowCookie(String name, String value, String path, String domain, int version, String comment,
                         int maxAge, Date expiry, boolean httpOnly) {
            super(name, value, path, domain, version, comment, maxAge, expiry, false, httpOnly);
        }

        public NowCookie(javax.ws.rs.core.Cookie cookie) {
            super(cookie);
        }

        public NowCookie(javax.ws.rs.core.Cookie cookie, String comment, int maxAge) {
            super(cookie, comment, maxAge, false);
        }

        public NowCookie(javax.ws.rs.core.Cookie cookie, String comment, int maxAge, Date expiry, boolean httpOnly) {
            super(cookie, comment, maxAge, expiry, false, httpOnly);
        }

        @Override
        public boolean isSecure() {
            return Requests.getSecurityContext().isSecure();
        }
    }
}
