package nl.first8.keycloak.saml.processing.api.saml.v2.request;

import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.PropertyPermission;

/**
 * Privileged Blocks
 *
 * @author Anil.Saldhana@redhat.com
 * @since Dec 9, 2008
 */
public class SecurityActions {

    private static String extractPackageNameFromClassName(final String fullyQualifiedName) {
        final int lastDot = fullyQualifiedName.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        return fullyQualifiedName.substring(0, lastDot);
    }

    /**
     * <p> Loads a {@link Class} using the <code>fullQualifiedName</code> supplied. This method tries first to load from
     * the specified {@link Class}, if not found it will try to load from using TCL. </p>
     *
     * @param theClass
     * @param fullQualifiedName
     *
     * @return
     */
    public static Class<?> loadClass(final Class<?> theClass, final String fullQualifiedName) {
        SecurityManager sm = System.getSecurityManager();

        if (fullQualifiedName == null) {
            return null;
        }

        if (sm != null) {
            sm.checkPackageDefinition(extractPackageNameFromClassName(fullQualifiedName));
            return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                @Override
                public Class<?> run() {
                    ClassLoader classLoader = theClass.getClassLoader();

                    Class<?> clazz = loadClass(classLoader, fullQualifiedName);
                    if (clazz == null) {
                        classLoader = Thread.currentThread().getContextClassLoader();
                        clazz = loadClass(classLoader, fullQualifiedName);
                    }
                    return clazz;
                }
            });
        } else {
            ClassLoader classLoader = theClass.getClassLoader();

            Class<?> clazz = loadClass(classLoader, fullQualifiedName);
            if (clazz == null) {
                classLoader = Thread.currentThread().getContextClassLoader();
                clazz = loadClass(classLoader, fullQualifiedName);
            }
            return clazz;
        }
    }

    /**
     * <p> Loads a class from the specified {@link ClassLoader} using the <code>fullQualifiedName</code> supplied. </p>
     *
     * @param classLoader
     * @param fullQualifiedName
     *
     * @return
     */
    public static Class<?> loadClass(final ClassLoader classLoader, final String fullQualifiedName) {
        SecurityManager sm = System.getSecurityManager();

        if (fullQualifiedName == null) {
            return null;
        }

        if (sm != null) {
            sm.checkPackageDefinition(extractPackageNameFromClassName(fullQualifiedName));
            return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                @Override
                public Class<?> run() {
                    try {
                        return classLoader.loadClass(fullQualifiedName);
                    } catch (ClassNotFoundException e) {
                    }
                    return null;
                }
            });
        } else {
            try {
                return classLoader.loadClass(fullQualifiedName);
            } catch (ClassNotFoundException e) {
            }
            return null;
        }
    }

    /**
     * Load a resource based on the passed {@link Class} classloader. Failing which try with the Thread Context CL
     *
     * @param clazz
     * @param resourceName
     *
     * @return
     */
    public static URL loadResource(final Class<?> clazz, final String resourceName) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<URL>() {
                @Override
                public URL run() {
                    URL url;
                    ClassLoader clazzLoader = clazz.getClassLoader();
                    url = clazzLoader.getResource(resourceName);

                    if (url == null) {
                        clazzLoader = Thread.currentThread().getContextClassLoader();
                        url = clazzLoader.getResource(resourceName);
                    }

                    return url;
                }
            });
        } else {
            URL url;
            ClassLoader clazzLoader = clazz.getClassLoader();
            url = clazzLoader.getResource(resourceName);

            if (url == null) {
                clazzLoader = Thread.currentThread().getContextClassLoader();
                url = clazzLoader.getResource(resourceName);
            }

            return url;
        }
    }

    /**
     * Set the system property
     *
     * @param key
     * @param defaultValue
     *
     * @return
     */
    public static void setSystemProperty(final String key, final String value) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new PropertyPermission(key, "write"));
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                @Override
                public Object run() {
                    System.setProperty(key, value);
                    return null;
                }
            });
        } else {
            System.setProperty(key, value);
        }
    }

    /**
     * <p>Returns a system property value using the specified <code>key</code>. If not found the
     * <code>defaultValue</code> will be returned.</p>
     *
     * @param key
     * @param defaultValue
     *
     * @return
     */
    public static String getSystemProperty(final String key, final String defaultValue) {
        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new PropertyPermission(key, "read"));
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    return System.getProperty(key, defaultValue);
                }
            });
        } else {
            return System.getProperty(key, defaultValue);
        }
    }

    /**
     * Get the Thread Context ClassLoader
     *
     * @return
     */
    public static ClassLoader getTCCL() {
        if (System.getSecurityManager() != null) {
            System.getSecurityManager().checkPermission(new RuntimePermission("getClassLoader"));
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                @Override
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        } else {
            return Thread.currentThread().getContextClassLoader();
        }
    }

    /**
     * Set the Thread Context ClassLoader
     *
     * @param paramCl
     */
    public static void setTCCL(final ClassLoader paramCl) {
        if (System.getSecurityManager() != null) {
            System.getSecurityManager().checkPermission(new RuntimePermission("setContextClassLoader"));
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    Thread.currentThread().setContextClassLoader(paramCl);
                    return null;
                }
            });
        } else {

            Thread.currentThread().setContextClassLoader(paramCl);
        }
    }

}