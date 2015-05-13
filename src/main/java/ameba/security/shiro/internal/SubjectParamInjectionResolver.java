package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.Auth;
import org.glassfish.jersey.server.internal.inject.ParamInjectionResolver;

/**
 * For method parameter injection with the {@linkplain Auth} annotation.
 *
 * @author icode
 */
public class SubjectParamInjectionResolver extends ParamInjectionResolver<Auth> {

    public SubjectParamInjectionResolver() {
        super(TypeFactory.class);
    }
}