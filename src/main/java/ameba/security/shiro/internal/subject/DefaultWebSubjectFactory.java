package ameba.security.shiro.internal.subject;

import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;

/**
 * @author icode
 */
public class DefaultWebSubjectFactory extends DefaultSubjectFactory {
    public Subject createSubject(SubjectContext context) {
        org.apache.shiro.mgt.SecurityManager securityManager = context.resolveSecurityManager();
        Session session = context.resolveSession();
        boolean sessionEnabled = context.isSessionCreationEnabled();
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();
        String host = context.resolveHost();

        return new DelegatingSubject(principals, authenticated, host, session, sessionEnabled, securityManager);
    }
}
