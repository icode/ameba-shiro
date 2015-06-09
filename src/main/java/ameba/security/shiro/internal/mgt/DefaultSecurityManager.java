package ameba.security.shiro.internal.mgt;

import ameba.security.shiro.internal.session.DefaultSessionManager;
import ameba.security.shiro.internal.subject.DefaultSubjectContext;
import ameba.security.shiro.internal.subject.DefaultSubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.SubjectContext;

import java.util.Collection;

/**
 * @author icode
 */
public class DefaultSecurityManager extends org.apache.shiro.mgt.DefaultSecurityManager {

    public DefaultSecurityManager() {
        super();
        setSubjectFactory(new DefaultSubjectFactory());
        setRememberMeManager(new CookieRememberMeManager());
        setSessionManager(new DefaultSessionManager());
    }

    public DefaultSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public DefaultSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    @Override
    protected SubjectContext createSubjectContext() {
        return new DefaultSubjectContext();
    }

    @Override
    protected SubjectContext copy(SubjectContext subjectContext) {
        return new DefaultSubjectContext(subjectContext);
    }
}
