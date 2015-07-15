package ameba.security.shiro;

import ameba.security.shiro.config.IniSecurityManagerFactory;
import ameba.security.shiro.filters.ShiroContainerFilter;
import ameba.security.shiro.internal.ShiroBinder;
import ameba.security.shiro.internal.ShiroDynamicFeature;
import ameba.security.shiro.internal.ShiroExceptionMapper;
import ameba.security.shiro.internal.mgt.DefaultSecurityManager;
import ameba.util.IOUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.Ini;
import org.apache.shiro.mgt.SecurityManager;
import org.glassfish.hk2.api.ServiceLocator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.io.InputStream;

/**
 * @author icode
 */
@Provider
public class ShiroFeature implements Feature {

    private static final Logger logger = LoggerFactory.getLogger(ShiroFeature.class);

    private static final String MAIN_SEC = "main";
    private static final String SECURITY_MANAGER = "securityManager";
    @Inject
    private ServiceLocator locator;

    @Override
    public boolean configure(FeatureContext context) {
        if (!context.getConfiguration().isRegistered(ShiroDynamicFeature.class)) {

            String conf = (String) context.getConfiguration().getProperty("security.shiro.conf");

            Ini ini = new Ini();

            InputStream in = IOUtils.getResourceAsStream(conf);
            if (in != null) {
                try {
                    ini.load(in);
                } finally {
                    IOUtils.closeQuietly(in);
                }
            } else {
                logger.warn("No Shiro configuration found.");
            }

            Ini.Section mainSection = ini.getSection(MAIN_SEC);
            if (!mainSection.containsKey(SECURITY_MANAGER)) {
                mainSection.put(SECURITY_MANAGER, DefaultSecurityManager.class.getName());
            }

            IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini, locator);
            final SecurityManager securityManager = factory.getInstance();

            SecurityUtils.setSecurityManager(securityManager);

            context.register(ShiroDynamicFeature.class)
                    .register(ShiroExceptionMapper.class)
                    .register(new ShiroBinder(securityManager))
                    .register(ShiroContainerFilter.class);

            return true;
        }
        return false;
    }
}