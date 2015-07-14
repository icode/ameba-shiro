package ameba.security.shiro.authz.permission;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;

/**
 * @author icode
 */
public class URIPermissionResolver implements PermissionResolver {

    /**
     * Returns a new {@link URIPermission URIPermission} instance constructed based on the specified
     * <tt>permissionString</tt>.
     *
     * @param permissionString the permission string to convert to a {@link Permission Permission} instance.
     * @return a new {@link URIPermission URIPermission} instance constructed based on the specified
     * <tt>permissionString</tt>
     */
    public Permission resolvePermission(String permissionString) {
        return new URIPermission(permissionString);
    }
}
