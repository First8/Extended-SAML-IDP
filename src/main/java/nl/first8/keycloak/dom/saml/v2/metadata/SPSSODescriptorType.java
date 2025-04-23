package nl.first8.keycloak.dom.saml.v2.metadata;

import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.SSODescriptorType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SPSSODescriptorType extends SSODescriptorType {
    protected List<IndexedEndpointType> assertionConsumerService = new ArrayList();
    protected List<AttributeConsumingServiceType> attributeConsumingService = new ArrayList();
    protected boolean authnRequestsSigned = false;
    protected boolean wantAssertionsSigned = false;

    public SPSSODescriptorType(List<String> protocolSupport) {
        super(protocolSupport);
    }

    public void addAssertionConsumerService(IndexedEndpointType assertionConsumer) {
        this.assertionConsumerService.add(assertionConsumer);
    }

    public void addAttributeConsumerService(AttributeConsumingServiceType attributeConsumer) {
        this.attributeConsumingService.add(attributeConsumer);
    }

    public void removeAssertionConsumerService(IndexedEndpointType assertionConsumer) {
        this.assertionConsumerService.remove(assertionConsumer);
    }

    public void removeAttributeConsumerService(AttributeConsumingServiceType attributeConsumer) {
        this.attributeConsumingService.remove(attributeConsumer);
    }

    public List<IndexedEndpointType> getAssertionConsumerService() {
        return Collections.unmodifiableList(this.assertionConsumerService);
    }

    public List<AttributeConsumingServiceType> getAttributeConsumingService() {
        return Collections.unmodifiableList(this.attributeConsumingService);
    }

    public Boolean isAuthnRequestsSigned() {
        return this.authnRequestsSigned;
    }

    public void setAuthnRequestsSigned(Boolean value) {
        this.authnRequestsSigned = value;
    }

    public Boolean isWantAssertionsSigned() {
        return this.wantAssertionsSigned;
    }

    public void setWantAssertionsSigned(Boolean value) {
        this.wantAssertionsSigned = value;
    }
}
