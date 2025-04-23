package nl.first8.keycloak.dom.saml.v2.assertion;

import org.keycloak.dom.saml.v2.assertion.AttributeType;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class XacmlResourceType {
    private final Set<AttributeType> attributes = new LinkedHashSet<AttributeType>();
    /**
     * Add a set of attributes
     *
     * @param xacmlResources {@link Collection}
     */
    public void addAttributes(Set<AttributeType> attributeTypes) {

        this.attributes.addAll(attributeTypes);
    }

    /**
     * Get a read only set of attributes
     *
     * @return {@link Set}
     */
    public Set<AttributeType> getAttributes() {
        checkSTSPermission();

        return Collections.unmodifiableSet(attributes);
    }

    protected void checkSTSPermission() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null)
            sm.checkPermission(new RuntimePermission("org.picketlink.sts"));
    }
}
