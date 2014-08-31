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
public class RequiresAuthenticationContainerRequestFilter extends ShiroContainerRequestFilter {
	@Override
	protected boolean isAccessAllowed(Subject subject) {
		return true;
	}

	@Override
	protected boolean isAuthorized(Subject subject) {
		return subject.isAuthenticated();
	}
}
