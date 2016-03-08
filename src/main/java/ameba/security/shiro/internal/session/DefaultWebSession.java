package ameba.security.shiro.internal.session;

import ameba.http.session.AbstractSession;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

/**
 * @author icode
 */
public class DefaultWebSession implements Session {


    private AbstractSession session;

    public DefaultWebSession(AbstractSession session) {
        this.session = session;
    }

    @Override
    public Serializable getId() {
        return session.getId();
    }

    @Override
    public Date getStartTimestamp() {
        return new Date(session.getTimestamp());
    }

    @Override
    public Date getLastAccessTime() {
        return new Date(System.currentTimeMillis());
    }

    @Override
    public long getTimeout() throws InvalidSessionException {
        return session.getTimeout();
    }

    @Override
    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        session.setTimeout(maxIdleTimeInMillis);
    }

    @Override
    public String getHost() {
        return session.getHost();
    }

    @Override
    public void touch() throws InvalidSessionException {
        session.touch();
    }

    @Override
    public void stop() throws InvalidSessionException {
        session.invalidate();
    }

    @Override
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return session.getAttributes().keySet();
    }

    @Override
    public Object getAttribute(Object key) throws InvalidSessionException {
        return session.getAttribute(key);
    }

    @Override
    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        session.setAttribute(key, value);
    }

    @Override
    public Object removeAttribute(Object key) throws InvalidSessionException {
        return session.removeAttribute(key);
    }
}
