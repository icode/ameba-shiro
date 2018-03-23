package ameba.security.shiro.filters;

import ameba.security.shiro.internal.mgt.CookieRememberMeManager;
import ameba.util.Cookies;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;

/**
 * @author icode
 */
@Priority(Priorities.AUTHENTICATION - 100)
@PreMatching
@Singleton
public class ShiroContainerFilter extends OncePerContainerFilter {

    @Inject
    private Provider<Subject> subjectProvider;

    @Override
    public void doFilter(ContainerRequestContext containerRequestContext) {
        ThreadContext.bind(subjectProvider.get());
    }

    @Override
    public void doFilter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        String removeRemember = (String) requestContext.getProperty(CookieRememberMeManager.RM_REMEMBER_COOKIE_KEY);
        if (StringUtils.isNotBlank(removeRemember)) {
            responseContext.getHeaders().add(HttpHeaders.SET_COOKIE, Cookies.newDeletedCookie(removeRemember));
        } else {
            Cookie addRemember = (Cookie) requestContext.getProperty(CookieRememberMeManager.ADD_REMEMBER_COOKIE_KEY);
            if (addRemember != null) {
                responseContext.getHeaders().add(HttpHeaders.SET_COOKIE, addRemember);
            }
        }
        ThreadContext.remove();
    }
}