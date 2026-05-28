package nl.first8.keycloak.saml.common;

import org.jboss.logging.Logger;
import org.keycloak.saml.common.PicketLinkLogger;

public class PicketLinkLoggerFactory {
    public static PicketLinkLogger getLogger(Logger logger) {
        return new DefaultPicketLinkLogger(logger);
    }
}
