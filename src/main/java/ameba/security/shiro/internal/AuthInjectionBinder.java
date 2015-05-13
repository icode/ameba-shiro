package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.Auth;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

import javax.inject.Singleton;

/**
 * @author icode
 */
public class AuthInjectionBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bind(SubjectParamInjectionResolver.class).in(Singleton.class)
                .to(new TypeLiteral<InjectionResolver<Auth>>() {
                });
    }
}