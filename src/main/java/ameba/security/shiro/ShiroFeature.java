package ameba.security.shiro;

import ameba.security.shiro.internal.AuthInjectionBinder;
import ameba.security.shiro.internal.ShiroDynamicFeature;
import ameba.security.shiro.internal.SubjectFactory;

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

/**
 * @author icode
 */
@Provider
public class ShiroFeature implements Feature {

    @Override
    public boolean configure(FeatureContext context) {
        if (!context.getConfiguration().isRegistered(ShiroDynamicFeature.class)) {
            context.register(new ShiroDynamicFeature())
                    .register(new SubjectFactory())
                    .register(new AuthInjectionBinder());
            return true;
        }
        return false;
    }
}