package ameba.security.shiro.internal;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.internal.inject.InjectionManager;
import org.glassfish.jersey.process.internal.RequestScoped;
import org.glassfish.jersey.server.spi.internal.ValueSupplierProvider;

/**
 * @author icode
 */
public class ShiroBinder extends AbstractBinder {

    private final InjectionManager injectionManager;
    private SecurityManager securityManager;

    public ShiroBinder(SecurityManager securityManager, InjectionManager injectionManager) {
        this.securityManager = securityManager;
        this.injectionManager = injectionManager;
    }

    @Override
    protected void configure() {
        bindFactory(SubjectValueSupplierProvider.SubjectFactory.class)
                .to(Subject.class)
                .in(RequestScoped.class);

        bind(securityManager)
                .to(SecurityManager.class)
                .to(Authenticator.class)
                .to(Authorizer.class)
                .to(SessionManager.class)
                .proxy(false);

        SubjectValueSupplierProvider beanSupplier =
                injectionManager.createAndInitialize(SubjectValueSupplierProvider.class);
        bindValueSupplier(beanSupplier);
    }

    private <T extends ValueSupplierProvider> void bindValueSupplier(T supplier) {
        bind(supplier).to(ValueSupplierProvider.class);
    }
}