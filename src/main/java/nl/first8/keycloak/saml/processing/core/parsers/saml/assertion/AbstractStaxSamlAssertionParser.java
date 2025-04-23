package nl.first8.keycloak.saml.processing.core.parsers.saml.assertion;

import org.keycloak.saml.common.parsers.AbstractStaxParser;
import org.keycloak.saml.processing.core.parsers.util.QNameEnumLookup;
import javax.xml.namespace.QName;

public abstract class AbstractStaxSamlAssertionParser<T> extends AbstractStaxParser<T, SAMLAssertionQNames> {

    protected static final QNameEnumLookup<SAMLAssertionQNames> LOOKUP = new QNameEnumLookup(SAMLAssertionQNames.values());

    public AbstractStaxSamlAssertionParser(SAMLAssertionQNames expectedStartElement) {
        super(expectedStartElement.getQName(), SAMLAssertionQNames.UNKNOWN_ELEMENT);

    }

    @Override
    protected SAMLAssertionQNames getElementFromName(QName name) {
        return LOOKUP.from(name);
    }

}
