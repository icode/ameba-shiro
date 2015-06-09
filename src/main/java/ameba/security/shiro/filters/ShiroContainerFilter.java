package ameba.security.shiro.filters;

import org.apache.shiro.util.ThreadContext;

import javax.annotation.Priority;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.PreMatching;

/**
 * @author icode
 */
@Priority(Priorities.AUTHENTICATION)
@PreMatching
@Singleton
public class ShiroContainerFilter extends OncePerContainerFilter {

    @Override
    public void doFilter(ContainerRequestContext containerRequestContext) {
        ThreadContext.bind(createSubject());
    }
}