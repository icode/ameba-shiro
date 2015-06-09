package ameba.security.shiro.filters;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

/**
 * @author icode
 */
public abstract class OncePerContainerFilter implements ContainerRequestFilter, ContainerResponseFilter {

    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";
    @Inject
    private SecurityManager securityManager;

    protected String getAlreadyFilteredAttributeName() {
        return getClass().getName() + ALREADY_FILTERED_SUFFIX;
    }

    protected Subject createSubject() {
        return new Subject.Builder(getSecurityManager()).buildSubject();
    }

    protected Boolean isFiltered(ContainerRequestContext containerRequestContext) {
        return containerRequestContext.getProperty(getAlreadyFilteredAttributeName()) != null;
    }

    @Override
    public final void filter(ContainerRequestContext containerRequestContext) {
        String name = getAlreadyFilteredAttributeName();
        if (!isFiltered(containerRequestContext)) {
            containerRequestContext.setProperty(name, Boolean.TRUE);
            doFilter(containerRequestContext);
        }
    }

    public void doFilter(ContainerRequestContext containerRequestContext) {

    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    @Override
    public final void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        if (isFiltered(requestContext)) {
            requestContext.removeProperty(getAlreadyFilteredAttributeName());
            doFilter(requestContext, responseContext);
        }
    }


    public void doFilter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {

    }
}