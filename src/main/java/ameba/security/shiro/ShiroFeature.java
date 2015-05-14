package ameba.security.shiro;

import ameba.security.shiro.internal.AuthInjectionBinder;
import ameba.security.shiro.internal.ShiroDynamicFeature;
import ameba.security.shiro.internal.ShiroExceptionMapper;
import ameba.security.shiro.internal.SubjectFactory;
import ameba.util.IOUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;

/**
 * @author icode
 */
@Provider
public class ShiroFeature implements Feature {

    private static final Logger logger = LoggerFactory.getLogger(ShiroFeature.class);

    @Override
    public boolean configure(FeatureContext context) {
        if (!context.getConfiguration().isRegistered(ShiroDynamicFeature.class)) {

            String conf = (String) context.getConfiguration().getProperty("security.shiro.conf");

            Ini ini = new Ini();

            Enumeration<URL> urls = IOUtils.getResources(conf);

            if (urls.hasMoreElements()) {
                while (urls.hasMoreElements()) {
                    URL url = urls.nextElement();
                    InputStream in = null;
                    try {
                        in = url.openStream();

                        ini.load(in);
                    } catch (IOException e) {
                        logger.warn("Load Shiro ini error", e);
                    } finally {
                        IOUtils.closeQuietly(in);
                    }
                }
            } else {
                logger.warn("No Shiro configuration found.");
            }

            IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
            final SecurityManager securityManager = factory.getInstance();
            SecurityUtils.setSecurityManager(securityManager);

            context.register(ShiroDynamicFeature.class)
                    .register(SubjectFactory.class)
                    .register(new AuthInjectionBinder())
                    .register(ShiroExceptionMapper.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(securityManager)
                                    .to(SecurityManager.class)
                                    .to(Authenticator.class)
                                    .to(Authorizer.class)
                                    .to(SessionManager.class)
                                    .proxy(false);
                        }
                    });

            return true;
        }
        return false;
    }
}