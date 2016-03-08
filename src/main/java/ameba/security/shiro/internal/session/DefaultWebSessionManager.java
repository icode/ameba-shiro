package ameba.security.shiro.internal.session;

import ameba.http.session.AbstractSession;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.AbstractSessionManager;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;

/**
 * @author icode
 */
public class DefaultWebSessionManager extends AbstractSessionManager {

    @Override
    public Session start(SessionContext context) {
        return getSession(true);
    }

    @Override
    public Session getSession(SessionKey key) throws SessionException {
        return getSession(false);
    }

    private Session getSession(boolean create) {
        AbstractSession session = ameba.http.session.Session.get(create);
        if (session != null)
            return new DefaultWebSession(session);
        else return null;
    }

}
