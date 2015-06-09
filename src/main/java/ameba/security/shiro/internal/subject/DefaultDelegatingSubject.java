package ameba.security.shiro.internal.subject;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DelegatingSubject;

/**
 * @author icode
 */
public class DefaultDelegatingSubject extends DelegatingSubject {
    public DefaultDelegatingSubject(org.apache.shiro.mgt.SecurityManager securityManager) {
        super(securityManager);
    }

    public DefaultDelegatingSubject(PrincipalCollection principals, boolean authenticated, String host, Session session, SecurityManager securityManager) {
        super(principals, authenticated, host, session, securityManager);
    }

    public DefaultDelegatingSubject(PrincipalCollection principals, boolean authenticated, String host, Session session, boolean sessionCreationEnabled, SecurityManager securityManager) {
        super(principals, authenticated, host, session, sessionCreationEnabled, securityManager);
    }

    @Override
    protected boolean isSessionCreationEnabled() {
        boolean enabled = super.isSessionCreationEnabled();
        return enabled && ameba.http.session.Session.get() != null;
    }
}
