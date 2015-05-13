package ameba.security.shiro;

import ameba.security.shiro.internal.AuthInjectionBinder;
import ameba.security.shiro.internal.ShiroDynamicFeature;
import ameba.security.shiro.internal.ShiroExceptionMapper;
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
            context.register(ShiroDynamicFeature.class)
                    .register(SubjectFactory.class)
                    .register(new AuthInjectionBinder())
                    .register(ShiroExceptionMapper.class);
            return true;
        }
        return false;
    }
}