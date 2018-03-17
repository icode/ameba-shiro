package ameba.security.shiro.internal.mgt;

import ameba.security.shiro.internal.session.DefaultWebSessionManager;
import ameba.security.shiro.internal.subject.DefaultWebSubjectContext;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.SubjectContext;

import java.util.Collection;

/**
 * @author icode
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager {

    public DefaultWebSecurityManager() {
        super();
        setSubjectFactory(new DefaultWebSubjectFactory());
        setRememberMeManager(new CookieRememberMeManager());
        setSessionManager(new DefaultWebSessionManager());
    }

    public DefaultWebSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    public DefaultWebSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    @Override
    protected SubjectContext createSubjectContext() {
        return new DefaultWebSubjectContext();
    }

    @Override
    protected SubjectContext copy(SubjectContext subjectContext) {
        if (subjectContext instanceof DefaultWebSubjectContext) {
            return new DefaultWebSubjectContext(subjectContext);
        }
        return super.copy(subjectContext);
    }
}
