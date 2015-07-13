package ameba.security.shiro.filters;

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

    public static boolean isMatchUri(Set<String[]> uris) {
        String path = Requests.getUriInfo().getPath();
        for (String[] uriWithM : uris) {
            if (uriWithM.length < 1) continue;
            String uri = uriWithM[0];
            if (StringUtils.isBlank(uri)) continue;

            if (uri.startsWith("/")) {
                uri = uri.substring(1);
            }
            if (isMatchMethod(uriWithM)) {
                if (uri.endsWith("**")) {
                    if (path.startsWith(uri.substring(0, uri.length() - 3))) {
                        return true;
                    }
                } else if (uri.endsWith("*")) {
                    int index = uri.length() - 2;
                    if (path.startsWith(uri.substring(0, index)) && path.indexOf(".", index + 1) == -1) {
                        return true;
                    }
                } else if (path.equals(uri)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isMatchMethod(String[] uri) {
        if (uri.length == 1) return true;
        if (uri.length == 2 && StringUtils.isBlank(uri[1])) return true;
        String m = Requests.getMethod();
        for (int i = 1; i < uri.length; i++) {
            if (m.equalsIgnoreCase(uri[i])) {
                return true;
            }
        }
        return false;
    }

    public static Set<String[]> getMatchUris(Map<String, Object> props, String key) {
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
        Set<String[]> ignore = Sets.newLinkedHashSet();
        for (String u : ignoreUris) {
            ignore.add(u.trim().split(" "));
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
