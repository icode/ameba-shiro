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
    private CookieTemplate cookie;

    public CookieRememberMeManager() {
        this.cookie = new CookieTemplate(
                DEFAULT_REMEMBER_ME_COOKIE_NAME,
                null,
                "/",
                null,
                CookieTemplate.DEFAULT_VERSION,
                null,
                COOKIE_MAX_AGE,
                null,
                true);
    }

    public CookieTemplate getCookie() {
        return cookie;
    }

    public void setCookie(CookieTemplate cookie) {
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
        CookieTemplate template = getCookie(); //the class attribute is really a template for the outgoing cookies
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

    public static class CookieTemplate extends Cookie {
        private String name;
        private String value;
        private int version;
        private String path;
        private String domain;
        private String comment;
        private int maxAge;
        private Date expiry;
        private Boolean secure = null;
        private boolean httpOnly;

        public CookieTemplate(String name,
                              String value,
                              String path,
                              String domain,
                              int version,
                              String comment,
                              int maxAge,
                              Date expiry,
                              boolean httpOnly) {
            super(name, null);
            this.name = name;
            this.value = value;
            this.path = path;
            this.domain = domain;
            this.version = version;
            this.comment = comment;
            this.maxAge = maxAge;
            this.expiry = expiry;
            this.httpOnly = httpOnly;
        }

        @Override
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        @Override
        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        @Override
        public int getVersion() {
            return version;
        }

        public void setVersion(int version) {
            this.version = version;
        }

        @Override
        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        @Override
        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getComment() {
            return comment;
        }

        public void setComment(String comment) {
            this.comment = comment;
        }

        public int getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(int maxAge) {
            this.maxAge = maxAge;
        }

        public Date getExpiry() {
            return expiry;
        }

        public void setExpiry(Date expiry) {
            this.expiry = expiry;
        }

        public boolean isHttpOnly() {
            return httpOnly;
        }

        public void setHttpOnly(boolean httpOnly) {
            this.httpOnly = httpOnly;
        }

        public boolean isSecure() {
            return secure == null ? Requests.getSecurityContext().isSecure() : secure;
        }

        public void setSecure(boolean secure) {
            this.secure = secure;
        }
    }
}
