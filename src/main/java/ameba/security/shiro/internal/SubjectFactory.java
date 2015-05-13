package ameba.security.shiro.internal;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.glassfish.hk2.api.PerLookup;

/**
 * @author icode
 */
public class SubjectFactory extends TypeFactory<Subject> {

    public SubjectFactory() {
        super(Subject.class);
    }

    @PerLookup
    @Override
    public Subject provide() {
        return SecurityUtils.getSubject();
    }
}
