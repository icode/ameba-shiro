package ameba.security.shiro.authz.permission;

import ameba.security.shiro.util.URIMatcher;
import org.apache.shiro.authz.Permission;

import java.io.Serializable;

/**
 * @author icode
 */
public class URIPermission implements Permission, Serializable {
    protected static final String PART_DIVIDER_TOKEN = ":";
    protected String uri;
    private URIMatcher matcher;

    public URIPermission(String uri) {
        this.uri = uri;
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
            String otherUri = ((URIPermission) p).uri;
            String[] um = otherUri.trim().split(PART_DIVIDER_TOKEN);
            return um.length > 1 && getMatcher().matches(um[0], um[1]);
        }
        return false;
    }
}
