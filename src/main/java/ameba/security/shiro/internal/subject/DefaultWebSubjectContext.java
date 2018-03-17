package ameba.security.shiro.internal.subject;

import ameba.http.session.Session;
import ameba.security.shiro.util.WebUtil;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import java.io.Serializable;

/**
 * @author icode
 */
public class DefaultWebSubjectContext extends DefaultSubjectContext {
    public DefaultWebSubjectContext() {
    }

    public DefaultWebSubjectContext(SubjectContext context) {
        super(context);
    }


    @Override
    public String resolveHost() {
        String host = super.resolveHost();
        if (host == null && WebUtil.hasSession()) {
            return Session.getHost();
        }
        return host;
    }

    @Override
    public Serializable getSessionId() {
        Serializable id = super.getSessionId();
        if (id == null && WebUtil.hasSession()) {
            return Session.getId();
        }
        return id;
    }
}
