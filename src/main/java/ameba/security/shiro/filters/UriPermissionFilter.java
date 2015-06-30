package ameba.security.shiro.filters;

import ameba.core.Application;
import org.apache.shiro.subject.Subject;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;
import java.util.Set;

/**
 * auto filter uris
 * <p/>
 * path/child/child:get
 * <p/>
 * path/child/child:post
 * <p/>
 * path/child/child:patch
 * <p/>
 * etc..
 *
 * @author icode
 */
@Singleton
@PreMatching
@Priority(Priorities.AUTHENTICATION + 100)
public class UriPermissionFilter extends ShiroContainerRequestFilter {

    private static final String IGN_KEY = "security.filter.uri.ignores";
    protected Set<String> ignoreUris;
    @Context
    private Provider<UriInfo> uriInfo;
    @Context
    private Provider<Request> requestProvider;
    @Inject
    private Application application;

    @PostConstruct
    private void postConstruct() {
        ignoreUris = FilterUtil.getIgnoreUris(application.getSrcProperties(), IGN_KEY);
        ignoreUris.add(FilterUtil.getLoginUrl(application.getSrcProperties()));
    }

    @Override
    protected boolean isAccessAllowed(Subject subject) {
        return FilterUtil.isIgnoreUri(ignoreUris)
                || subject.isPermitted(
                uriInfo.get().getPath() + ":" + requestProvider.get().getMethod().toLowerCase()
        );
    }
}
