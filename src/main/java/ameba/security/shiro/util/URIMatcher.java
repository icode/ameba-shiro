package ameba.security.shiro.util;

import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;
import java.net.URI;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author icode
 */
public class URIMatcher implements Serializable {
    protected static final Pattern URI_REGEX = Pattern.compile("\\{(.*?)\\}");
    protected static final String WILDCARD_TOKEN = "*";

    private Set<String> methods = Sets.newHashSet();
    private String uri;
    private Pattern uriPattern;
    private boolean hasQuery;
    private boolean preMatch;
    private boolean oneDepthMatch;
    private int oneDepthMatchLength;

    private boolean uriRegex = false;


    public URIMatcher(String uriWithM) {
        String[] um = uriWithM.trim().split(":");
        init(um[0], um.length > 1 ? um[1].split("\\s+") : new String[]{WILDCARD_TOKEN});
    }

    public URIMatcher(String uri, String... m) {
        init(uri, m);
    }

    protected void init(String _uri, String[] m) {
        this.uri = _uri.trim();
        if (m != null && m.length > 0) {
            for (String mt : m) {
                if (StringUtils.isNotBlank(mt)) {
                    methods.add(mt.trim().toUpperCase());
                }
            }
        }

        if (!this.uri.startsWith("/")) {
            this.uri = "/" + this.uri;
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
        this.hasQuery = this.uri.contains("\\?");
        if (this.uriRegex) {
            int endIndex = this.uri.length() - 1;
            if (start < endIndex) {
                regex.append(Pattern.quote(this.uri.substring(start, this.uri.length())));
            }
            regex.append("$");
            uriPattern = Pattern.compile(regex.toString());
        } else {
            this.preMatch = this.uri.endsWith("**");
            if (this.preMatch) {
                this.uri = this.uri.substring(0, this.uri.length() - 2);
            } else {
                this.oneDepthMatch = this.uri.endsWith("*");
                if (this.oneDepthMatch) {
                    int index = this.uri.length() - 1;
                    this.uri = this.uri.substring(0, index);
                    this.oneDepthMatchLength = index;
                }
            }
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
            String path = reqUri.getPath();
            if (hasQuery) {
                path += ("?" + reqUri.getQuery());
            }
            if (isUriRegex()) {
                return getUriPattern().matcher(path).matches();
            } else {
                if (preMatch) {
                    if (!path.endsWith("/")) {
                        path += "/";
                    }
                    return path.startsWith(uri);
                } else if (oneDepthMatch) {
                    if (path.length() < uri.length()) {
                        path += "/";
                    }
                    return path.startsWith(uri)
                            && (path.length() <= oneDepthMatchLength
                            || path.indexOf("/", oneDepthMatchLength) == -1);
                } else return path.equals(uri);
            }
        }
        return false;
    }
}
