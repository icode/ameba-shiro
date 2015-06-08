package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.Auth;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

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
        bind(SubjectParamInjectionResolver.class).in(Singleton.class)
                .to(new TypeLiteral<InjectionResolver<Auth>>() {
                });
        bind(securityManager)
                .to(SecurityManager.class)
                .to(Authenticator.class)
                .to(Authorizer.class)
                .to(SessionManager.class)
                .proxy(false);
    }
}