package nl.first8.keycloak.dom.saml.v2.metadata;

import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AttributeConsumingServiceType  {

    protected static List<AttributeConsumingService> attributeConsumingServices ;

    protected List<LocalizedNameType> serviceName = new ArrayList();
    protected List<LocalizedNameType> serviceDescription = new ArrayList();
    protected List<AttributeType> requestedAttribute = new ArrayList();
    protected int index;
    protected Boolean isDefault;

    public static List<AttributeConsumingService> getAttributeConsumingServices() {
        return attributeConsumingServices;
    }
    public static void setAttributeConsumingServices( List<AttributeConsumingService> attributeConsumingServices) {
        AttributeConsumingServiceType.attributeConsumingServices = attributeConsumingServices;
    }

    public AttributeConsumingServiceType(int index) {
        this.isDefault = Boolean.FALSE;
        this.index = index;
    }

    public void addServiceName(LocalizedNameType service) {
        this.serviceName.add(service);
    }

    public void addServiceDescription(LocalizedNameType desc) {
        this.serviceDescription.add(desc);
    }

    public void addRequestedAttribute(AttributeType req) {
        this.requestedAttribute.add(req);
    }

    public void removeServiceName(LocalizedNameType service) {
        this.serviceName.remove(service);
    }

    public void removeServiceDescription(LocalizedNameType desc) {
        this.serviceDescription.remove(desc);
    }

    public void removeRequestedAttribute(org.keycloak.dom.saml.v2.metadata.RequestedAttributeType req) {
        this.requestedAttribute.remove(req);
    }

    public List<LocalizedNameType> getServiceName() {
        return Collections.unmodifiableList(this.serviceName);
    }

    public List<LocalizedNameType> getServiceDescription() {
        return Collections.unmodifiableList(this.serviceDescription);
    }

    public List<AttributeType> getRequestedAttribute() {
        return Collections.unmodifiableList(this.requestedAttribute);
    }

    public int getIndex() {
        return this.index;
    }

    public Boolean isIsDefault() {
        return this.isDefault;
    }

    public void setIsDefault(Boolean value) {
        this.isDefault = value;
    }
}