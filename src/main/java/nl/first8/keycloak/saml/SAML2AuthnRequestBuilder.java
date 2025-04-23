package nl.first8.keycloak.saml;

import nl.first8.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.dom.saml.v2.protocol.ScopingType;
import org.keycloak.saml.SAML2NameIDBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SAML2RequestedAuthnContextBuilder;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.w3c.dom.Document;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;

public class SAML2AuthnRequestBuilder implements SamlProtocolExtensionsAwareBuilder<SAML2AuthnRequestBuilder> {

    private final AuthnRequestType authnRequestType;
    protected String destination;
    protected NameIDType issuer;
    protected final List<NodeGenerator> extensions = new LinkedList<>();
    protected ScopingType scoping;

    public SAML2AuthnRequestBuilder destination(String destination) {
        this.destination = destination;
        return this;
    }

    public SAML2AuthnRequestBuilder issuer(NameIDType issuer) {
        this.issuer = issuer;
        return this;
    }

    public SAML2AuthnRequestBuilder issuer(String issuer) {
        return issuer(SAML2NameIDBuilder.value(issuer).build());
    }

    @Override
    public SAML2AuthnRequestBuilder addExtension(NodeGenerator extension) {
        this.extensions.add(extension);
        return this;
    }

    public SAML2AuthnRequestBuilder() {
        this.authnRequestType = new AuthnRequestType(IDGenerator.create("ID_"), XMLTimeUtil.getIssueInstant());
    }

    public SAML2AuthnRequestBuilder assertionConsumerUrl(String assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(URI.create(assertionConsumerUrl));
        return this;
    }

    public SAML2AuthnRequestBuilder assertionConsumerUrl(URI assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(assertionConsumerUrl);
        return this;
    }

    public SAML2AuthnRequestBuilder assertionConsumerIndex(int assertionConsumerIndex) {
        this.authnRequestType.setAssertionConsumerServiceIndex(assertionConsumerIndex);
        return this;
    }

    public SAML2AuthnRequestBuilder attributeConsumingServiceIndex(Integer attributeConsumingServiceIndex) {
        this.authnRequestType.setAttributeConsumingServiceIndex(attributeConsumingServiceIndex);
        return this;
    }

    public SAML2AuthnRequestBuilder forceAuthn(boolean forceAuthn) {
        this.authnRequestType.setForceAuthn(forceAuthn);
        return this;
    }

    public SAML2AuthnRequestBuilder isPassive(boolean isPassive) {
        this.authnRequestType.setIsPassive(isPassive);
        return this;
    }

    public SAML2AuthnRequestBuilder nameIdPolicy(SAML2NameIDPolicyBuilder nameIDPolicyBuilder) {
        this.authnRequestType.setNameIDPolicy(nameIDPolicyBuilder.build());
        return this;
    }

    public SAML2AuthnRequestBuilder protocolBinding(String protocolBinding) {
        this.authnRequestType.setProtocolBinding(URI.create(protocolBinding));
        return this;
    }

    public SAML2AuthnRequestBuilder subject(String subject) {
        String sanitizedSubject = subject != null ? subject.trim() : null;
        if (sanitizedSubject != null && !sanitizedSubject.isEmpty()) {
            this.authnRequestType.setSubject(createSubject(sanitizedSubject));
        }
        return this;
    }

    private SubjectType createSubject(String value) {
        NameIDType nameId = new NameIDType();
        nameId.setValue(value);
        nameId.setFormat(this.authnRequestType.getNameIDPolicy() != null ? this.authnRequestType.getNameIDPolicy().getFormat() : null);
        SubjectType subject = new SubjectType();
        SubjectType.STSubType subType = new SubjectType.STSubType();
        subType.addBaseID(nameId);
        subject.setSubType(subType);
        return subject;
    }

    public SAML2AuthnRequestBuilder requestedAuthnContext(SAML2RequestedAuthnContextBuilder requestedAuthnContextBuilder) {
        RequestedAuthnContextType requestedAuthnContext = requestedAuthnContextBuilder.build();

        // Only emit the RequestedAuthnContext element if at least a ClassRef or a DeclRef is present
        if (!requestedAuthnContext.getAuthnContextClassRef().isEmpty() ||
            !requestedAuthnContext.getAuthnContextDeclRef().isEmpty())
            this.authnRequestType.setRequestedAuthnContext(requestedAuthnContext);

        return this;
    }

    public SAML2AuthnRequestBuilder scoping(ScopingType scoping) {
        this.scoping = scoping;
        return this;
    }

    public Document toDocument() {
        try {
            AuthnRequestType authnRequestType = createAuthnRequest();

            return SAML2Request.convert(authnRequestType);
        } catch (Exception e) {
            throw new RuntimeException("Could not convert " + authnRequestType + " to a document.", e);
        }
    }

    public AuthnRequestType createAuthnRequest() {
        AuthnRequestType res = this.authnRequestType;

        res.setIssuer(issuer);
        res.setDestination(URI.create(this.destination));
        res.setScoping(scoping);

        if (! this.extensions.isEmpty()) {
            ExtensionsType extensionsType = new ExtensionsType();
            for (NodeGenerator extension : this.extensions) {
                extensionsType.addExtension(extension);
            }
            res.setExtensions(extensionsType);
        }

        return res;
    }
}
