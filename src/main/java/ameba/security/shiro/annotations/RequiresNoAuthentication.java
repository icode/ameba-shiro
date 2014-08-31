package ameba.security.shiro.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Use this marker annotation to remove class requirement of
 * {@link org.apache.shiro.authz.annotation.RequiresAuthentication} on a method.
 *
 * @author icode
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresNoAuthentication {
}
