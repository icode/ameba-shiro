package ameba.security.shiro.internal.mgt;

import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

/**
 * @author icode
 */
public class CookieRememberMeManager extends AbstractRememberMeManager {
    @Override
    protected void forgetIdentity(Subject subject) {

    }

    @Override
    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {

    }

    @Override
    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
        return new byte[0];
    }

    @Override
    public void forgetIdentity(SubjectContext subjectContext) {

    }
}
