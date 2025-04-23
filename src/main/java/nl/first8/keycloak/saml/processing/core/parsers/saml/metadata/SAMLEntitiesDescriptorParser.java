package nl.first8.keycloak.saml.processing.core.parsers.saml.metadata;

import nl.first8.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.metadata.AbstractStaxSamlMetadataParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLExtensionsParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLMetadataQNames;
import org.w3c.dom.Element;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

public class SAMLEntitiesDescriptorParser  extends AbstractStaxSamlMetadataParser<EntitiesDescriptorType> {
    private static final SAMLEntitiesDescriptorParser INSTANCE = new SAMLEntitiesDescriptorParser();

    public SAMLEntitiesDescriptorParser() {
        super(SAMLMetadataQNames.ENTITIES_DESCRIPTOR);
    }

    public static SAMLEntitiesDescriptorParser getInstance() {
        return INSTANCE;
    }

    protected EntitiesDescriptorType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        EntitiesDescriptorType descriptor = new EntitiesDescriptorType();
        descriptor.setID(StaxParserUtil.getAttributeValue(element, SAMLMetadataQNames.ATTR_ID));
        descriptor.setValidUntil(StaxParserUtil.getXmlTimeAttributeValue(element, SAMLMetadataQNames.ATTR_VALID_UNTIL));
        descriptor.setCacheDuration(StaxParserUtil.getXmlDurationAttributeValue(element, SAMLMetadataQNames.ATTR_CACHE_DURATION));
        descriptor.setName(StaxParserUtil.getAttributeValue(element, SAMLMetadataQNames.ATTR_NAME));
        return descriptor;
    }

    protected void processSubElement(XMLEventReader xmlEventReader, EntitiesDescriptorType target, SAMLMetadataQNames element, StartElement elementDetail) throws ParsingException {
        switch(element) {
            case SIGNATURE:
                Element sig = StaxParserUtil.getDOMElement(xmlEventReader);
                target.setSignature(sig);
                break;
            case EXTENSIONS:
                target.setExtensions((ExtensionsType) SAMLExtensionsParser.getInstance().parse(xmlEventReader));
                break;
            case ENTITY_DESCRIPTOR:
                target.addEntityDescriptor(SAMLEntityDescriptorParser.getInstance().parse(xmlEventReader));
                break;
            case ENTITIES_DESCRIPTOR:
                target.addEntityDescriptor(this.parse(xmlEventReader));
                break;
            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }

    }
}
