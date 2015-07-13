package ameba.security.shiro.filters;

import ameba.core.Application;
import com.google.common.base.Charsets;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.subject.Subject;
import org.glassfish.jersey.server.ExtendedUriInfo;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
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
public class UserFilter implements ContainerRequestFilter {
    protected Set<String[]> ignoreUris;
    protected Set<String[]> uris;
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
        uris = FilterUtil.getMatchUris(application.getSrcProperties(), "security.filter.user.uris");
        ignoreUris = FilterUtil.getMatchUris(application.getSrcProperties(), "security.filter.user.ignoreUris");
        loginUrl = FilterUtil.getLoginUrl(application.getSrcProperties());
        ignoreUris.add(loginUrl.split(" "));
    }

    public void filter(ContainerRequestContext requestContext) throws IOException {
        if ((uris.size() == 0 || FilterUtil.isMatchUri(uris)) && !FilterUtil.isMatchUri(ignoreUris)) {
            if (FilterUtil.isVisitPage(requestContext)) {
                Subject subject = subjectProvider.get();
                if (subject == null || (!subject.isAuthenticated() && !subject.isRemembered())) {
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
                }
            }
        }
    }
}
