package nl.first8.keycloak.dom.saml.v2.assertion;

import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.assertion.StatementAbstractType;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AttributeStatementType extends StatementAbstractType {

    protected List<ASTChoiceType> attributes = new ArrayList<>();
    protected List<SAMLEncryptedAttribute> encryptedAttributes = new ArrayList<>();

    /**
     * Add an attribute
     *
     * @param attribute
     */
    public void addAttribute(ASTChoiceType attribute) {
        attributes.add(attribute);
    }

    /**
     * Remove an attribute
     *
     * @param attribute
     */
    public void removeAttribute(ASTChoiceType attribute) {
        attributes.remove(attribute);
    }

    /**
     * Gets the attributes.
     *
     * @return a read only {@link List}
     */
    public List<ASTChoiceType> getAttributes() {
        return Collections.unmodifiableList(this.attributes);
    }

    public void addAttributes(List<ASTChoiceType> attributes) {
        this.attributes.addAll(attributes);
    }

    public void addEncryptedAttribute(SAMLEncryptedAttribute encryptedAttribute) {
        encryptedAttributes.add(encryptedAttribute);
    }

    public void removeEncryptedAttribute(SAMLEncryptedAttribute encryptedAttribute) {
        encryptedAttributes.remove(encryptedAttribute);
    }

    public List<SAMLEncryptedAttribute> getEncryptedAttributes() {
        return Collections.unmodifiableList(this.encryptedAttributes);
    }

    public static class ASTChoiceType implements Serializable {

        private AttributeType attribute;
        private EncryptedElementType encryptedAssertion;

        public ASTChoiceType(AttributeType attribute) {
            super();
            this.attribute = attribute;
        }

        public ASTChoiceType(EncryptedElementType encryptedAssertion) {
            super();
            this.encryptedAssertion = encryptedAssertion;
        }

        public AttributeType getAttribute() {
            return attribute;
        }

        public EncryptedElementType getEncryptedAssertion() {
            return encryptedAssertion;
        }
    }
}