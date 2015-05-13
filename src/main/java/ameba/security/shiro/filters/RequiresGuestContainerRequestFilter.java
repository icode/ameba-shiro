package ameba.security.shiro.filters;

import org.apache.shiro.subject.Subject;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ext.Provider;

/**
 * @author icode
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class RequiresGuestContainerRequestFilter extends ShiroContainerRequestFilter {
    @Override
    protected boolean isAccessAllowed(Subject subject) {
        return !subject.isAuthenticated() && !subject.isRemembered();
    }

    @Override
    protected boolean isAuthorized(Subject subject) {
        // To get the UNAUTHORIZED error, we skip it here.
        return true;
    }
}
