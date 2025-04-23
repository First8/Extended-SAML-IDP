package nl.first8.keycloak.dom.saml.v2.metadata;

import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.w3c.dom.Element;

import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EntitiesDescriptorType {
    protected Element signature;
    protected ExtensionsType extensions;
    protected List<Object> entityDescriptor = new ArrayList();
    protected XMLGregorianCalendar validUntil;
    protected Duration cacheDuration;
    protected String id;
    protected String name;

    public EntitiesDescriptorType() {
    }

    public Element getSignature() {
        return this.signature;
    }

    public void setSignature(Element value) {
        this.signature = value;
    }

    public ExtensionsType getExtensions() {
        return this.extensions;
    }

    public void setExtensions(ExtensionsType value) {
        this.extensions = value;
    }

    public void addEntityDescriptor(Object obj) {
        this.entityDescriptor.add(obj);
    }

    public void removeEntityDescriptor(Object obj) {
        this.entityDescriptor.remove(obj);
    }

    public List<Object> getEntityDescriptor() {
        return Collections.unmodifiableList(this.entityDescriptor);
    }

    public XMLGregorianCalendar getValidUntil() {
        return this.validUntil;
    }

    public void setValidUntil(XMLGregorianCalendar value) {
        this.validUntil = value;
    }

    public Duration getCacheDuration() {
        return this.cacheDuration;
    }

    public void setCacheDuration(Duration value) {
        this.cacheDuration = value;
    }

    public String getID() {
        return this.id;
    }

    public void setID(String value) {
        this.id = value;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String value) {
        this.name = value;
    }
}