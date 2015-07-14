package ameba.security.shiro.util;

import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author icode
 */
public class URIMatcher {
    protected static final Pattern URI_REGEX = Pattern.compile("\\{(.*?)\\}");
    protected static final String WILDCARD_TOKEN = "*";

    private Set<String> methods = Sets.newHashSet();
    private String uri;
    private Pattern uriPattern;

    private boolean uriRegex = false;


    public URIMatcher(String uriWithM) {
        String[] um = uriWithM.trim().split(":");
        init(um[0], um.length > 1 ? um[1].split("\\s+") : new String[]{WILDCARD_TOKEN});
    }

    public URIMatcher(String uri, String... m) {
        init(uri, m);
    }

    protected void init(String uri, String[] m) {
        this.uri = uri.trim();
        if (m != null && m.length > 0) {
            for (String mt : m) {
                if (StringUtils.isNotBlank(mt)) {
                    methods.add(mt.trim().toUpperCase());
                }
            }
        }
        if (this.uri.startsWith("/")) {
            this.uri = this.uri.substring(1);
        }

        Matcher matcher = URI_REGEX.matcher(this.uri);
        StringBuilder regex = new StringBuilder("^");
        int start = 0;
        while (matcher.find()) {
            this.uriRegex = true;
            int ms = matcher.start();
            regex.append(Pattern.quote(this.uri.substring(start, ms)));
            start = matcher.end();
            regex.append(matcher.group(1));
        }
        if (this.uriRegex) {
            regex.append("$");
            uriPattern = Pattern.compile(regex.toString());
        }
    }

    public boolean isUriRegex() {
        return uriRegex;
    }

    public Set<String> getMethods() {
        return methods;
    }

    public String getUri() {
        return uri;
    }

    public Pattern getUriPattern() {
        return uriPattern;
    }

    public boolean matches(URI reqUri, String method) {
        if (getMethods().contains(WILDCARD_TOKEN)
                || getMethods().contains(method)) {
            String uri = getUri();
            String path;
            if (isUriRegex()) {

                boolean hasFr = uri.contains("#");
                boolean hasQr = uri.contains("\\?");

                if (!hasFr && !hasQr) {
                    path = reqUri.getPath();
                } else if (hasFr) {
                    path = reqUri.getPath() + "#" + reqUri.getFragment();
                } else {
                    path = reqUri.getPath() + "?" + reqUri.getQuery();
                }
                if (getUriPattern().matcher(path).matches()) {
                    return true;
                }
            } else {
                path = reqUri.getPath();
                
                if (uri.endsWith("**")) {
                    if (path.startsWith(uri.substring(0, uri.length() - 3))) {
                        return true;
                    }
                } else if (uri.endsWith("*")) {
                    int index = uri.length() - 2;
                    if (path.startsWith(uri.substring(0, index)) && path.indexOf("/", index + 1) == -1) {
                        return true;
                    }
                } else if (path.equals(uri)) {
                    return true;
                }
            }
        }
        return false;
    }
}
