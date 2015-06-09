package ameba.security.shiro.internal.session;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.session.mgt.SessionManager;

/**
 * @author icode
 */
public class DefaultSessionManager implements SessionManager {

    @Override
    public Session start(SessionContext context) {
        return getSession();
    }

    @Override
    public Session getSession(SessionKey key) throws SessionException {
        return getSession();
    }

    private Session getSession() {
        return new DefaultSession(ameba.http.session.Session.get());
    }

}
