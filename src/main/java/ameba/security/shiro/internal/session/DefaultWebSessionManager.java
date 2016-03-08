package ameba.security.shiro.internal.session;

import ameba.http.session.AbstractSession;
import ameba.security.shiro.internal.mgt.DefaultWebSessionFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionKey;

/**
 * @author icode
 */
public class DefaultWebSessionManager extends DefaultSessionManager {

    public DefaultWebSessionManager() {
        super();
        setSessionFactory(new DefaultWebSessionFactory());
    }

    @Override
    public Session getSession(SessionKey key) throws SessionException {
        AbstractSession session = ameba.http.session.Session.get(false);
        if (session != null)
            return new DefaultWebSession(session);
        else return null;
    }
}
