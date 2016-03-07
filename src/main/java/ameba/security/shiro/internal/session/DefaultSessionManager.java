package ameba.security.shiro.internal.session;

import ameba.http.session.AbstractSession;
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
        AbstractSession session = ameba.http.session.Session.get(false);
        if (session != null)
            return new DefaultSession(session);
        else return null;
    }

}
