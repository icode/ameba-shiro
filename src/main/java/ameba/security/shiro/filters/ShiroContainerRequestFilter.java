package ameba.security.shiro.filters;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;

/**
 * @author icode
 */
abstract class ShiroContainerRequestFilter implements ContainerRequestFilter {

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
        Subject subject = SecurityUtils.getSubject();
        if (!isAuthorized(subject)) {
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity(
                    "Unauthorized").build());
        } else if (!isAccessAllowed(subject)) {
            containerRequestContext.abortWith(Response.status(Response.Status.FORBIDDEN).entity(
                    "Forbidden").build());
        }
    }

}