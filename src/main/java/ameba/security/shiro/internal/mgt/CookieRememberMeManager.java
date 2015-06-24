package ameba.security.shiro.internal.mgt;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author icode
 */
public class CookieRememberMeManager extends AbstractRememberMeManager {
    public static final String DEFAULT_REMEMBER_ME_COOKIE_NAME = "r";
    private static final Logger logger = LoggerFactory.getLogger(CookieRememberMeManager.class);

    @Override
    protected void forgetIdentity(Subject subject) {

    }

    @Override
    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        String base64 = Base64.encodeToString(serialized);

    }

    @Override
    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
        return new byte[0];
    }

    @Override
    public void forgetIdentity(SubjectContext subjectContext) {

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
}
