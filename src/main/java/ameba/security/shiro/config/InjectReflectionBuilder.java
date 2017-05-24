package ameba.security.shiro.config;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.ReflectionBuilder;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.Nameable;
import org.glassfish.jersey.internal.inject.InjectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * @author icode
 */
public class InjectReflectionBuilder extends ReflectionBuilder {
    private static final Logger logger = LoggerFactory.getLogger(InjectReflectionBuilder.class);
    private InjectionManager injectionManager;

    public InjectReflectionBuilder(InjectionManager injectionManager) {
        this.injectionManager = injectionManager;
    }

    public InjectReflectionBuilder(Map<String, ?> defaults, InjectionManager injectionManager) {
        super(defaults);
        this.injectionManager = injectionManager;
    }

    @Override
    protected void createNewInstance(Map<String, Object> objects, String name, String value) {
        Object currentInstance = objects.get(name);
        if (currentInstance != null) {
            logger.debug("An instance with name '{}' already exists.  " +
                    "Redefining this object as a new instance of type {}", name, value);
        }

        Object instance;//name with no property, assume right hand side of equals sign is the class name:
        try {
            instance = injectionManager.createAndInitialize(ClassUtils.forName(value));
            if (instance instanceof Nameable) {
                ((Nameable) instance).setName(name);
            }
        } catch (Exception e) {
            String msg = "Unable to instantiate class [" + value + "] for object named '" + name + "'.  " +
                    "Please ensure you've specified the fully qualified class name correctly.";
            throw new ConfigurationException(msg, e);
        }
        objects.put(name, instance);
    }
}
