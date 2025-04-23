package nl.first8.keycloak.dom.saml.v2.protocol;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.EncryptedAssertionType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ResponseType extends StatusResponseType {

    protected List<RTChoiceType> assertions = new ArrayList<>();

    public ResponseType(String id, XMLGregorianCalendar issueInstant) {
        super(id, issueInstant);
    }

    public ResponseType(StatusResponseType srt) {
        super(srt);
    }

    /**
     * Add an assertion
     *
     * @param choice
     */
    public void addAssertion(RTChoiceType choice) {
        assertions.add(choice);
    }

    /**
     * Remove an assertion
     *
     * @param choice
     */
    public void removeAssertion(RTChoiceType choice) {
        assertions.remove(choice);
    }

    /**
     * Replace the first assertion with the passed assertion
     *
     * @param id id of the old assertion
     * @param newAssertion
     */
    public void replaceAssertion(String id, RTChoiceType newAssertion) {
        int index = 0;
        if (id != null && !id.isEmpty()) {
            for (RTChoiceType assertion : assertions) {
                if (assertion.getID().equals(id)) {
                    break;
                }
                index++;
            }
        }
        assertions.remove(index);
        assertions.add(index, newAssertion);
    }

    /**
     * Gets a read only list of assertions
     */
    public List<RTChoiceType> getAssertions() {
        return Collections.unmodifiableList(assertions);
    }

    public static class RTChoiceType {

        private AssertionType assertion;

        private EncryptedAssertionType encryptedAssertion;

        private String id;

        public RTChoiceType(AssertionType assertion) {
            this.assertion = assertion;
            this.id = assertion.getID();
        }

        public RTChoiceType(EncryptedAssertionType encryptedAssertion) {
            this.encryptedAssertion = encryptedAssertion;

        }

        public AssertionType getAssertion() {
            return assertion;
        }

        public EncryptedAssertionType getEncryptedAssertion() {
            return encryptedAssertion;
        }

        public String getID() {
            return id;
        }
    }
}