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
public class RequiresUserContainerRequestFilter extends ShiroContainerRequestFilter {
    @Override
    protected boolean isAccessAllowed(Subject subject) {
        // If checkAuthorization succeeds, the user is allowed.
        return true;
    }
}
