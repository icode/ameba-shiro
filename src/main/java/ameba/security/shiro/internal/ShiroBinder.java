package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.Security;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.process.internal.RequestScoped;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Singleton;

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

        bindFactory(SubjectValueProvider.SubjectFactory.class)
                .to(Subject.class)
                .in(RequestScoped.class);

        bind(SubjectValueProvider.class)
                .to(ValueFactoryProvider.class)
                .in(Singleton.class);

        bind(SubjectValueProvider.InjectionResolver.class)
                .to(new TypeLiteral<InjectionResolver<Security>>() {
                }).in(Singleton.class);

        bind(securityManager)
                .to(SecurityManager.class)
                .to(Authenticator.class)
                .to(Authorizer.class)
                .to(SessionManager.class)
                .proxy(false);
    }
}