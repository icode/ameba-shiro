package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.Auth;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.jersey.server.internal.inject.AbstractValueFactoryProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.internal.inject.ParamInjectionResolver;
import org.glassfish.jersey.server.model.Parameter;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * @author icode
 */
public class SubjectValueProvider extends AbstractValueFactoryProvider {

    @Inject
    protected SubjectValueProvider(MultivaluedParameterExtractorProvider mpep, ServiceLocator locator) {
        super(mpep, locator, Parameter.Source.UNKNOWN);
    }

    @Override
    protected Factory<?> createValueFactory(Parameter parameter) {
        Class type = parameter.getRawType();
        if (Subject.class.isAssignableFrom(type))
            return new SubjectFactory();

        return null;
    }

    static final class SubjectFactory implements Factory<Subject> {

        @Override
        public Subject provide() {
            return SecurityUtils.getSubject();
        }

        @Override
        public void dispose(Subject subject) {

        }
    }

    @Singleton
    static final class InjectionResolver extends ParamInjectionResolver<Auth> {

        public InjectionResolver() {
            super(SubjectValueProvider.class);
        }
    }
}
