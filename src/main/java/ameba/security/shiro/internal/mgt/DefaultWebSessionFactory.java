package ameba.security.shiro.internal.mgt;

import ameba.http.session.AbstractSession;
import ameba.security.shiro.internal.session.DefaultWebSession;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionFactory;

/**
 * @author icode
 */
public class DefaultWebSessionFactory implements SessionFactory {
    @Override
    public Session createSession(SessionContext initData) {
        AbstractSession session = ameba.http.session.Session.get(true);
        return new DefaultWebSession(session);
    }
}
