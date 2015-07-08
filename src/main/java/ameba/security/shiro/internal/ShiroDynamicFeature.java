package ameba.security.shiro.internal;

import ameba.security.shiro.annotations.*;
import ameba.security.shiro.filters.*;
import org.apache.shiro.authz.annotation.*;
import org.glassfish.hk2.api.ServiceLocator;

import javax.inject.Inject;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.lang.annotation.Annotation;

/**
 * @author icode
 */
@Provider
public class ShiroDynamicFeature implements DynamicFeature {

    @Inject
    private ServiceLocator locator;

    private boolean filterNeeded(Class<? extends Annotation> requireAnnotationClass,
                                 Class<? extends Annotation> antiRequireAnnotationClass,
                                 ResourceInfo resourceInfo) {
        return (resourceInfo.getResourceClass().getAnnotation(requireAnnotationClass) != null
                || resourceInfo.getResourceMethod().getAnnotation(requireAnnotationClass) != null) &&
                resourceInfo.getResourceMethod().getAnnotation(antiRequireAnnotationClass) == null;
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
        // No need to check non-Jax-rs classes
        if (filterNeeded(RequiresAuthentication.class, RequiresNoAuthentication.class, resourceInfo)) {
            featureContext.register(locator.createAndInitialize(RequiresAuthenticationContainerRequestFilter.class));
        }

        if (filterNeeded(RequiresGuest.class, RequiresNoGuest.class, resourceInfo)) {
            featureContext.register(locator.createAndInitialize(RequiresGuestContainerRequestFilter.class));
        }

        if (filterNeeded(RequiresPermissions.class, RequiresNoPermission.class, resourceInfo)) {
            ShiroContainerRequestFilter filter = new RequiresPermissionContainerRequestFilter(resourceInfo);
            locator.inject(filter);
            locator.postConstruct(filter);
            featureContext.register(filter);
        }

        if (filterNeeded(RequiresRoles.class, RequiresNoRoles.class, resourceInfo)) {
            ShiroContainerRequestFilter filter = new RequiresRolesContainerRequestFilter(resourceInfo);
            locator.inject(filter);
            locator.postConstruct(filter);
            featureContext.register(filter);
        }

        if (filterNeeded(RequiresUser.class, RequiresNoUser.class, resourceInfo)) {
            featureContext.register(locator.createAndInitialize(RequiresUserContainerRequestFilter.class));
        }
    }
}