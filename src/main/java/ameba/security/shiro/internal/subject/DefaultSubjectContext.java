package ameba.security.shiro.internal.subject;

import ameba.http.session.Session;
import org.apache.shiro.subject.SubjectContext;

import java.io.Serializable;

/**
 * @author icode
 */
public class DefaultSubjectContext extends org.apache.shiro.subject.support.DefaultSubjectContext {
    public DefaultSubjectContext() {
    }

    public DefaultSubjectContext(SubjectContext context) {
        super(context);
    }


    @Override
    public String resolveHost() {
        String host = super.resolveHost();
        if (host == null && Session.get(false) != null) {
            return Session.getHost();
        }
        return host;
    }

    @Override
    public Serializable getSessionId() {
        return Session.get(false) != null ? Session.getId() : null;
    }


}
