package ameba.security.shiro.internal;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.process.internal.RequestScoped;

import javax.inject.Inject;
import java.util.function.Supplier;

/**
 * @author icode
 */
public class ShiroBinder extends AbstractBinder {

    private SecurityManager securityManager;

    public ShiroBinder(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    @Override
    protected void configure() {
        bindFactory(SubjectFactory.class)
                .to(Subject.class)
                .in(RequestScoped.class);
        bind(securityManager)
                .to(SecurityManager.class)
                .to(Authenticator.class)
                .to(Authorizer.class)
                .to(SessionManager.class)
                .proxy(false);
    }

    static final class SubjectFactory implements Supplier<Subject> {

        @Inject
        private SecurityManager manager;

        @Override
        public Subject get() {
            return new Subject.Builder(manager).buildSubject();
        }
    }
}