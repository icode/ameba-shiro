package ameba.security.shiro.authz.permission;

import ameba.security.shiro.util.URIMatcher;
import org.apache.shiro.authz.Permission;

import java.io.Serializable;
import java.net.URI;

/**
 * @author icode
 */
public class URIPermission implements Permission, Serializable {
    protected static final String PART_DIVIDER_TOKEN = ":";
    protected String uri;
    protected URI requestUri;
    protected String method;
    private URIMatcher matcher;

    public URIPermission(String uri) {
        this.uri = uri;
    }

    public URIPermission(URI requestUri, String method) {
        this.requestUri = requestUri;
        this.method = method;
    }

    public URIMatcher getMatcher() {
        if (matcher == null) {
            synchronized (this) {
                if (matcher == null) {
                    matcher = new URIMatcher(uri);
                }
            }
        }
        return matcher;
    }

    @Override
    public boolean implies(Permission p) {
        if (p instanceof URIPermission) {
            URIPermission op = ((URIPermission) p);
            if (op.method == null) {
                String otherUri = op.uri;
                String[] um = otherUri.trim().split(PART_DIVIDER_TOKEN);
                return um.length > 1 && getMatcher().matches(URI.create(um[0]), um[1]);
            } else if (op.requestUri != null) {
                return getMatcher().matches(op.requestUri, op.method);
            }
        }
        return false;
    }
}
