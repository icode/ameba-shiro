package ameba.security.shiro.filters;

import ameba.core.Application;
import ameba.security.shiro.util.FilterUtil;
import ameba.security.shiro.util.URIMatcher;
import com.google.common.base.Charsets;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.subject.Subject;
import org.glassfish.jersey.server.ExtendedUriInfo;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Set;

/**
 * @author icode
 */
@Singleton
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class AuthenticateFilter implements ContainerRequestFilter {
    public static final String AUTHENTICATED = AuthenticateFilter.class.getName() + "AUTHENTICATED";

    protected Set<URIMatcher> ignoreUris;
    protected Set<URIMatcher> uris;
    private String loginUrl = "/login";
    private String callbackParam = "callback";
    @Context
    private Provider<Subject> subjectProvider;
    @Context
    private Provider<ExtendedUriInfo> uriInfoProvider;
    @Inject
    private Application application;

    @PostConstruct
    private void postConstruct() {
        String callbackParam = (String) application.getProperty("security.login.param.callback");
        if (StringUtils.isNotBlank(callbackParam)) {
            this.callbackParam = StringUtils.deleteWhitespace(callbackParam);
        }
        uris = FilterUtil.getMatchUris(application.getSrcProperties(), "security.filter.authenticate.uris");
        ignoreUris = FilterUtil.getMatchUris(application.getSrcProperties(), "security.filter.authenticate.ignoreUris");
        ignoreUris.addAll(FilterUtil.getMatchUris(application.getSrcProperties(), "security.filter.ignoreUris"));
        loginUrl = FilterUtil.getLoginUrl(application.getSrcProperties());
        ignoreUris.add(new URIMatcher(loginUrl));
    }

    /**
     * 当前身份是否被授权（是否记住我或已经授权）
     *
     * @return 检查当前身份
     */
    protected boolean isAuthorized(Subject subject) {
        return subject.isRemembered() || subject.isAuthenticated();
    }

    public void filter(ContainerRequestContext requestContext) throws IOException {
        if ((uris.size() == 0 || FilterUtil.isMatchUri(uris)) && !FilterUtil.isMatchUri(ignoreUris)) {
            Subject subject = subjectProvider.get();
            if (subject == null || (!isAuthorized(subject))) {
                if (FilterUtil.isVisitPage(requestContext)) {
                    StringBuilder login = new StringBuilder(loginUrl);
                    if (!"disabled".equalsIgnoreCase(callbackParam)) {
                        login.append("?")
                                .append(callbackParam)
                                .append("=")
                                .append(
                                        URLEncoder.encode(
                                                uriInfoProvider.get().getRequestUri().toString(),
                                                Charsets.UTF_8.name()
                                        )
                                );
                    }
                    URI loginUri = URI.create(login.toString());
                    requestContext.abortWith(Response.temporaryRedirect(loginUri).build());
                } else {
                    throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
                }
            }
        }
        requestContext.setProperty(AUTHENTICATED, true);
    }
}
