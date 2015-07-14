package ameba.security.shiro.filters;

import ameba.core.Application;
import ameba.security.shiro.authz.permission.URIPermission;
import ameba.security.shiro.util.FilterUtil;
import ameba.security.shiro.util.URIMatcher;
import org.apache.shiro.subject.Subject;
import org.glassfish.jersey.server.ExtendedUriInfo;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;
import java.util.Map;
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

    private static final String IGN_KEY = "security.filter.ignoreUris";
    private static final String URIS_KEY = "security.filter.uris";
    protected Set<URIMatcher> ignoreUris;
    protected Set<URIMatcher> uris;
    @Context
    private Provider<ExtendedUriInfo> uriInfo;
    @Context
    private Provider<Request> requestProvider;
    @Inject
    private Application application;

    @PostConstruct
    private void postConstruct() {
        Map<String, Object> map = application.getSrcProperties();
        ignoreUris = FilterUtil.getMatchUris(map, IGN_KEY);
        ignoreUris.add(new URIMatcher(FilterUtil.getLoginUrl(map)));
        uris = FilterUtil.getMatchUris(map, URIS_KEY);
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        if (!FilterUtil.isMatchUri(ignoreUris)
                && (uris.size() == 0 || FilterUtil.isMatchUri(uris))) {
            super.filter(containerRequestContext);
        }
    }

    @Override
    protected boolean isAccessAllowed(Subject subject) {
        UriInfo ui = uriInfo.get();
        return subject.isPermitted(new URIPermission(ui.getRequestUri(), requestProvider.get().getMethod()));
    }
}
