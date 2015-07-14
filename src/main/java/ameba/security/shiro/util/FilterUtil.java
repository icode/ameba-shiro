package ameba.security.shiro.util;

import ameba.core.Requests;
import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author icode
 */
public class FilterUtil {
    public static final String DEFAULT_LOGIN_URL = "/login";
    private static final MediaType LOW_IE_DEFAULT_REQ_TYPE = new MediaType("application", "x-ms-application");

    private FilterUtil() {
    }

    public static String getLoginUrl(Map<String, Object> props) {
        String loginUrl = DEFAULT_LOGIN_URL;
        String loginUrlStr = (String) props.get("security.login.url");
        if (StringUtils.isNotBlank(loginUrlStr)) {
            loginUrl = StringUtils.deleteWhitespace(loginUrlStr);
            if (loginUrl.endsWith("/")) {
                loginUrl = loginUrl.substring(0, loginUrl.length() - 2);
            }
            if (loginUrl.startsWith("/")) {
                loginUrl = loginUrl.substring(1);
            }
        }
        return loginUrl;
    }

    public static boolean isMatchUri(Set<URIMatcher> matchers) {
        String path = Requests.getUriInfo().getPath();
        String method = Requests.getMethod();
        for (URIMatcher matcher : matchers) {
            if (matcher.matches(path, method)) {
                return true;
            }
        }
        return false;
    }

    public static Set<URIMatcher> getMatchUris(Map<String, Object> props, String key) {
        Set<String> ignoreUris = Sets.newLinkedHashSet();
        String ignores = (String) props.get(key);
        if (StringUtils.isNotBlank(ignores)) {
            Collections.addAll(ignoreUris, ignores.split(","));
        }
        key += ".";
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            if (entry.getKey().startsWith(key)) {
                ignores = (String) entry.getValue();
                if (StringUtils.isNotBlank(ignores)) {
                    Collections.addAll(ignoreUris, ignores.split(","));
                }
            }
        }
        Set<URIMatcher> ignore = Sets.newLinkedHashSet();
        for (String u : ignoreUris) {
            ignore.add(new URIMatcher(u));
        }
        return ignore;
    }


    public static boolean isVisitPage(ContainerRequestContext requestContext) {
        List<MediaType> mediaTypes = requestContext.getAcceptableMediaTypes();
        return (mediaTypes.size() == 0
                || mediaTypes.contains(MediaType.TEXT_HTML_TYPE)
                || mediaTypes.contains(LOW_IE_DEFAULT_REQ_TYPE));
    }
}
