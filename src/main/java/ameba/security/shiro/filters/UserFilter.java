package ameba.security.shiro.filters;

import ameba.core.Application;
import com.google.common.base.Charsets;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.subject.Subject;

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
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.List;

/**
 * @author icode
 */
@Priority(Priorities.AUTHENTICATION)
@Singleton
@PreMatching
public class UserFilter implements ContainerRequestFilter {
    private static final MediaType LOW_IE_DEFAULT_REQ_TYPE = new MediaType("application", "x-ms-application");
    private static String LOGIN_URL = "/login";
    private static String CALL_BACK_PARAM = "callback";
    private static String[] IGNORE_URIS = new String[0];

    @Context
    private Provider<Subject> subjectProvider;
    @Context
    private Provider<UriInfo> uriInfo;
    @Inject
    private Application application;

    @PostConstruct
    private void postConstruct() {
        String loginUrl = (String) application.getProperty("security.login.url");
        if (StringUtils.isNotBlank(loginUrl)) {
            LOGIN_URL = StringUtils.deleteWhitespace(loginUrl);
            if (LOGIN_URL.endsWith("/")) {
                LOGIN_URL = LOGIN_URL.substring(0, LOGIN_URL.length() - 2);
            }
        }
        String callbackParam = (String) application.getProperty("security.login.param.callback");
        if (StringUtils.isNotBlank(callbackParam)) {
            CALL_BACK_PARAM = StringUtils.deleteWhitespace(callbackParam);
        }
        String ignoreUris = (String) application.getProperty("security.filter.user.ignoreUris");
        if (StringUtils.isNotBlank(ignoreUris)) {
            IGNORE_URIS = StringUtils.deleteWhitespace(ignoreUris).split(",");
        }
    }

    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!isIgnoreUri()) {
            if (isVistPage(requestContext)) {
                Subject subject = subjectProvider.get();
                if (subject == null || (!subject.isAuthenticated() && !subject.isRemembered())) {
                    StringBuilder login = new StringBuilder(LOGIN_URL);
                    if (!"disabled".equalsIgnoreCase(CALL_BACK_PARAM)) {
                        login.append("?")
                                .append(CALL_BACK_PARAM)
                                .append("=")
                                .append(
                                        URLEncoder.encode(
                                                uriInfo.get().getRequestUri().toString(),
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

    private boolean isVistPage(ContainerRequestContext requestContext) {
        List<MediaType> mediaTypes = requestContext.getAcceptableMediaTypes();
        return (mediaTypes.size() == 0
                || mediaTypes.contains(MediaType.TEXT_HTML_TYPE)
                || mediaTypes.contains(LOW_IE_DEFAULT_REQ_TYPE));
    }

    private String getLoginUrl() {
        return LOGIN_URL.startsWith("/") ? LOGIN_URL.substring(1) : LOGIN_URL;
    }

    private boolean isIgnoreUri() {
        String path = uriInfo.get().getPath();
        if (path.startsWith("assets/")
                || path.equals(getLoginUrl())) {
            return true;
        }
        for (String uri : IGNORE_URIS) {
            if (uri.startsWith("/")) {
                uri = uri.substring(1);
            }
            if (uri.endsWith("*")) {
                if (path.startsWith(uri.substring(0, uri.length() - 2))) {
                    return true;
                }
            } else if (path.equals(uri)) {
                return true;
            }
        }
        return false;
    }
}
