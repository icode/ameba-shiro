package ameba.security.shiro.filters;

import org.apache.shiro.subject.Subject;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;

import static ameba.security.shiro.filters.AuthenticateFilter.AUTHENTICATED;

/**
 * @author icode
 */
public abstract class ShiroContainerRequestFilter implements ContainerRequestFilter {

    @Inject
    protected Provider<Subject> subjectProvider;

    /**
     * @return 返回当前是否拥有权限
     */
    protected abstract boolean isAccessAllowed(Subject subject);

    /**
     * 当前身份是否被授权（是否记住我或已经授权）
     *
     * @return 检查当前身份
     */
    boolean isAuthorized(Subject subject) {
        return subject.isRemembered() || subject.isAuthenticated();
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        Object authenticated = containerRequestContext.getProperty(AUTHENTICATED);
        Subject subject = subjectProvider.get();
        if (authenticated == null && !isAuthorized(subject)) {
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
        } else if (!isAccessAllowed(subject)) {
            throw new ForbiddenException();
        }
    }

}