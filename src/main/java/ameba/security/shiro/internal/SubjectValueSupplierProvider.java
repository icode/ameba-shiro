package ameba.security.shiro.internal;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.glassfish.hk2.api.Factory;
import org.glassfish.jersey.internal.inject.InjectionManager;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.internal.inject.AbstractRequestDerivedValueSupplier;
import org.glassfish.jersey.server.internal.inject.AbstractValueSupplierProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.model.Parameter;

import javax.inject.Inject;
import javax.inject.Provider;

/**
 * @author icode
 */
public class SubjectValueSupplierProvider extends AbstractValueSupplierProvider {

    private InjectionManager injectionManager;

    @Inject
    protected SubjectValueSupplierProvider(MultivaluedParameterExtractorProvider mpep,
                                           Provider<ContainerRequest> requestProvider,
                                           InjectionManager injectionManager) {
        super(mpep, requestProvider, Parameter.Source.UNKNOWN);
        this.injectionManager = injectionManager;
    }

    @Override
    protected AbstractRequestDerivedValueSupplier<?> createValueSupplier(
            Parameter parameter, Provider<ContainerRequest> provider) {
        Class type = parameter.getRawType();
        if (Subject.class.isAssignableFrom(type))
            return new AbstractRequestDerivedValueSupplier<Subject>(provider) {
                @Override
                public Subject get() {
                    return injectionManager.getInstance(Subject.class);
                }
            };

        return null;
    }

    static final class SubjectFactory implements Factory<Subject> {

        @Inject
        private SecurityManager manager;

        @Override
        public Subject provide() {
            return new Subject.Builder(manager).buildSubject();
        }

        @Override
        public void dispose(Subject subject) {

        }
    }
}
