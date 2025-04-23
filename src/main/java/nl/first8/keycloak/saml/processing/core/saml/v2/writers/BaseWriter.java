package nl.first8.keycloak.saml.processing.core.saml.v2.writers;

import nl.first8.keycloak.dom.saml.v2.assertion.SAMLEncryptedType;
import nl.first8.keycloak.dom.saml.v2.assertion.SamlEncryptedId;
import nl.first8.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.BaseIDAbstractType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.assertion.KeyInfoConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.xmlsec.w3.xmldsig.KeyInfoType;
import org.keycloak.dom.xmlsec.w3.xmlenc.*;
import org.keycloak.saml.common.PicketLinkLogger;
import org.keycloak.saml.common.PicketLinkLoggerFactory;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.util.StaxWriterUtil;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.PROTOCOL_NSURI;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class BaseWriter {

    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    protected static String PROTOCOL_PREFIX = "samlp";

    protected static String ASSERTION_PREFIX = "saml";

    protected XMLStreamWriter writer = null;

    public BaseWriter(XMLStreamWriter writer) {
        this.writer = writer;
    }

    /**
     * Write {@code NameIDType} to stream
     *
     * @param nameIDType
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(NameIDType nameIDType, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        URI format = nameIDType.getFormat();
        if (format != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.FORMAT.get(), format.toASCIIString());
        }

        String spProvidedID = nameIDType.getSPProvidedID();
        if (StringUtil.isNotNull(spProvidedID)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.SP_PROVIDED_ID.get(), spProvidedID);
        }

        String spNameQualifier = nameIDType.getSPNameQualifier();
        if (StringUtil.isNotNull(spNameQualifier)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.SP_NAME_QUALIFIER.get(), spNameQualifier);
        }

        String nameQualifier = nameIDType.getNameQualifier();
        if (StringUtil.isNotNull(nameQualifier)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME_QUALIFIER.get(), nameQualifier);
        }

        String value = nameIDType.getValue();
        if (StringUtil.isNotNull(value)) {
            StaxUtil.writeCharacters(writer, value);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code SAMLEncryptedType} to stream
     *
     * @param samlEncryptedType
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(SAMLEncryptedType samlEncryptedType, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        write(samlEncryptedType.getEncryptedData(), JBossSAMLConstants.ENCRYPTED_DATA.getAsQName());

        List<EncryptedKeyType> encryptedKeys = samlEncryptedType.getEncryptedKeys();
        for (EncryptedKeyType encryptedKey : encryptedKeys) {
            write(encryptedKey, JBossSAMLConstants.ENCRYPTED_KEY.getAsQName());
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code EncryptedDataType} to stream
     *
     * @param encryptedDataType
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(EncryptedDataType encryptedDataType, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        String id = encryptedDataType.getId();
        if (StringUtil.isNotNull(id)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), id);
        }

        String type = encryptedDataType.getType();
        if (StringUtil.isNotNull(type)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.TYPE.get(), type);
        }

        EncryptionMethodType encryptionMethod = encryptedDataType.getEncryptionMethod();
        if (encryptionMethod != null) {
            write(encryptionMethod, JBossSAMLConstants.ENCRYPTION_METHOD.getAsQName());
        }
        KeyInfoType keyInfo = encryptedDataType.getKeyInfo();
        if(keyInfo != null) {
            write(keyInfo, JBossSAMLConstants.KEY_INFO.getAsQName());
        }

        CipherDataType cipherData = encryptedDataType.getCipherData();
        if(cipherData != null) {
            write(cipherData, JBossSAMLConstants.CIPHER_DATA.getAsQName());
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code EncryptionMethodType} to stream
     *
     * @param encryptionMethod
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(EncryptionMethodType encryptionMethod, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        String algorithm = encryptionMethod.getAlgorithm();
        if(StringUtil.isNotNull(algorithm)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.ALGORITHM.get(), algorithm);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code KeyInfoType} to stream
     *
     * @param keyInfoType
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(KeyInfoType keyInfoType, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        logger.debug("Not yet Implemented writing RetrievalMethod");

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code CipherDataType} to stream
     *
     * @param cipherData
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(CipherDataType cipherData, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        String cipherValue = new String(cipherData.getCipherValue());
        if(StringUtil.isNotNull(cipherValue)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.CIPHER_VALUE.get(), cipherValue);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code EncryptedKeyType} to stream
     *
     * @param encryptedKey
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(EncryptedKeyType encryptedKey, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        String id = encryptedKey.getId();
        if(StringUtil.isNotNull(id)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), id);
        }

        String recipient = encryptedKey.getRecipient();
        if(StringUtil.isNotNull(recipient)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.RECIPIENT.get(), recipient);
        }

        EncryptionMethodType encryptionMethod = encryptedKey.getEncryptionMethod();
        if(encryptionMethod != null) {
            write(encryptionMethod, JBossSAMLConstants.ENCRYPTION_METHOD.getAsQName());
        }

        KeyInfoType keyInfo = encryptedKey.getKeyInfo();
        if(keyInfo != null) {
            write(keyInfo, JBossSAMLConstants.KEY_INFO.getAsQName());
        }

        CipherDataType cipherData = encryptedKey.getCipherData();
        if(cipherData != null) {
            write(cipherData, JBossSAMLConstants.CIPHER_DATA.getAsQName());
        }

        ReferenceList referenceList = encryptedKey.getReferenceList();
        if(referenceList != null) {
            write(referenceList, JBossSAMLConstants.REFERENCE_LIST.getAsQName());
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code ReferenceList} to stream
     *
     * @param referenceList
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(ReferenceList referenceList, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        List<ReferenceList.References> references = referenceList.getReferences();
        for (ReferenceList.References reference : references) {
            ReferenceType dataReference = reference.getDataReference();
            if(dataReference != null) {
                write(dataReference, JBossSAMLConstants.DATA_REFERENCE.getAsQName());
            }
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code ReferenceType} to stream
     *
     * @param dataReference
     * @param tag
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(ReferenceType dataReference, QName tag, boolean writeNamespace) throws ProcessingException {
        StaxUtil.writeStartElement(writer, tag.getPrefix(), tag.getLocalPart(), tag.getNamespaceURI());

        if (writeNamespace) {
            StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        }

        String uri = dataReference.getURI().toString();
        if(StringUtil.isNotNull(uri)) {
            StaxUtil.writeAttribute(writer, "URI", uri);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write {@code NameIDType} to stream without writing a namespace
     */
    public void write(NameIDType nameIDType, QName tag) throws ProcessingException {
        this.write(nameIDType, tag, false);
    }

    /**
     * Write {@code SamlEncryptedId} to stream without writing a namespace
     */
    public void write(SamlEncryptedId samlEncryptedId, QName tag) throws ProcessingException {
        this.write(samlEncryptedId, tag, false);
    }

    /**
     * Write {@code EncryptedDataType} to stream without writing a namespace
     */
    public void write(EncryptedDataType encryptedDataType, QName tag) throws ProcessingException {
        this.write(encryptedDataType, tag, false);
    }

    /**
     * Write {@code EncryptionMethodType} to stream without writing a namespace
     */
    private void write(EncryptionMethodType encryptionMethod, QName tag) throws ProcessingException {
        this.write(encryptionMethod, tag, false);
    }

    /**
     * Write {@code KeyInfoType} to stream without writing a namespace
     */
    private void write(KeyInfoType keyInfoType, QName tag) throws ProcessingException {
        this.write(keyInfoType, tag, false);
    }

    /**
     * Write {@code CipherDataType} to stream without writing a namespace
     */
    private void write(CipherDataType cipherDataType, QName tag) throws ProcessingException {
        this.write(cipherDataType, tag, false);
    }

    /**
     * Write {@code CipherDataType} to stream without writing a namespace
     */
    private void write(EncryptedKeyType encryptedKey, QName tag) throws ProcessingException {
        this.write(encryptedKey, tag, false);
    }

    /**
     * Write {@code ReferenceList} to stream without writing a namespace
     */
    private void write(ReferenceList referenceList, QName tag) throws ProcessingException {
        this.write(referenceList, tag, false);
    }

    /**
     * Write {@code ReferenceType} to stream without writing a namespace
     */
    private void write(ReferenceType reference, QName tag) throws ProcessingException {
        this.write(reference, tag, false);
    }

    /**
     * Write an {@code AttributeType} to stream
     *
     * @param attributeType
     *
     * @throws ProcessingException
     */
    public void write(AttributeType attributeType) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE.get(), ASSERTION_NSURI.get());

        writeAttributeTypeWithoutRootTag(attributeType);

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    public void writeAttributeTypeWithoutRootTag(AttributeType attributeType) throws ProcessingException {
        String attributeName = attributeType.getName();
        if (attributeName != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME.get(), attributeName);
        }

        String friendlyName = attributeType.getFriendlyName();
        if (StringUtil.isNotNull(friendlyName)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.FRIENDLY_NAME.get(), friendlyName);
        }

        String nameFormat = attributeType.getNameFormat();
        if (StringUtil.isNotNull(nameFormat)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME_FORMAT.get(), nameFormat);
        }

        // Take care of other attributes such as x500:encoding
        Map<QName, String> otherAttribs = attributeType.getOtherAttributes();
        if (otherAttribs != null) {
            List<String> nameSpacesDealt = new ArrayList<>();

            Iterator<QName> keySet = otherAttribs.keySet().iterator();
            while (keySet != null && keySet.hasNext()) {
                QName qname = keySet.next();
                String ns = qname.getNamespaceURI();
                if (!nameSpacesDealt.contains(ns)) {
                    StaxUtil.writeNameSpace(writer, qname.getPrefix(), ns);
                    nameSpacesDealt.add(ns);
                }
                String attribValue = otherAttribs.get(qname);
                StaxUtil.writeAttribute(writer, qname, attribValue);
            }
        }

        List<Object> attributeValues = attributeType.getAttributeValue();
        if (attributeValues != null) {
            for (Object attributeValue : attributeValues) {
                if (attributeValue != null) {
                    if (attributeValue instanceof String) {
                        writeStringAttributeValue((String) attributeValue);
                    } else if (attributeValue instanceof NameIDType) {
                    	writeNameIDTypeAttributeValue((NameIDType) attributeValue);
                    } else if (attributeValue instanceof XMLGregorianCalendar) {
                        writeDateAttributeValue((XMLGregorianCalendar) attributeValue);
                    } else if (attributeValue instanceof Element) {
                        writeElementAttributeValue((Element) attributeValue);
                    } else if (attributeValue instanceof SamlEncryptedId) {
                        logger.debug("EncryptedID is not implemented yet.");
                    } else
                        throw logger.writerUnsupportedAttributeValueError(attributeValue.getClass().getName());
                } else {
                    writeStringAttributeValue(null);
                }
            }
        }
    }

    private void writeElementAttributeValue(Element attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(),
                ASSERTION_NSURI.get());
        StaxUtil.writeDOMElement(writer, attributeValue);
        StaxUtil.writeEndElement(writer);
    }

    public void writeNameIDTypeAttributeValue(NameIDType attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());
    	write((NameIDType)attributeValue, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
        StaxUtil.writeEndElement(writer);
    }

    public void writeEncryptedIDAttributeValue(SamlEncryptedId attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());
        write((SamlEncryptedId)attributeValue, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.ENCRYPTED_ID.get(), ASSERTION_PREFIX));
        StaxUtil.writeEndElement(writer);
    }

    public void writeStringAttributeValue(String attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());

        StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        StaxUtil.writeNameSpace(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());
        StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:string");

        if (attributeValue == null) {
            StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "nil", "true");
        } else {
            StaxUtil.writeCharacters(writer, attributeValue);
        }

        StaxUtil.writeEndElement(writer);
    }

    public void writeDateAttributeValue(XMLGregorianCalendar attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());

        StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        StaxUtil.writeNameSpace(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());
        StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:" + attributeValue.getXMLSchemaType().getLocalPart());

        if (attributeValue == null) {
            StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "nil", "true");
        } else {
            StaxUtil.writeCharacters(writer, attributeValue.toString());
        }

        StaxUtil.writeEndElement(writer);
    }

    public void writeLocalizedNameType(LocalizedNameType localizedNameType, QName startElement) throws ProcessingException {
        StaxUtil.writeStartElement(writer, startElement.getPrefix(), startElement.getLocalPart(),
                startElement.getNamespaceURI());
        StaxUtil.writeAttribute(writer, new QName(JBossSAMLURIConstants.XML.get(), "lang", "xml"), localizedNameType.getLang());
        StaxUtil.writeCharacters(writer, localizedNameType.getValue());
        StaxUtil.writeEndElement(writer);
    }

    /**
     * write an {@code SubjectType} to stream
     *
     * @param subject
     * @param out
     *
     * @throws ProcessingException
     */
    public void write(SubjectType subject) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT.get(), ASSERTION_NSURI.get());

        SubjectType.STSubType subType = subject.getSubType();
        if (subType != null) {
            BaseIDAbstractType baseID = subType.getBaseID();
            if (baseID instanceof NameIDType) {
                NameIDType nameIDType = (NameIDType) baseID;
                write(nameIDType, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
            }
            EncryptedElementType enc = subType.getEncryptedID();
            if (enc != null)
                throw new RuntimeException("NYI");
            List<SubjectConfirmationType> confirmations = subType.getConfirmation();
            if (confirmations != null) {
                for (SubjectConfirmationType confirmation : confirmations) {
                    write(confirmation);
                }
            }
        }
        List<SubjectConfirmationType> subjectConfirmations = subject.getConfirmation();
        if (subjectConfirmations != null) {
            for (SubjectConfirmationType subjectConfirmationType : subjectConfirmations) {
                write(subjectConfirmationType);
            }
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    public void write(ExtensionsType extensions) throws ProcessingException {
        if (extensions.getAny().isEmpty()) {
            return;
        }

        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.EXTENSIONS__PROTOCOL.get(), PROTOCOL_NSURI.get());

        for (Object o : extensions.getAny()) {
            if (o instanceof Node) {
                StaxUtil.writeDOMNode(writer, (Node) o);
            } else if (o instanceof SamlProtocolExtensionsAwareBuilder.NodeGenerator) {
                SamlProtocolExtensionsAwareBuilder.NodeGenerator ng = (SamlProtocolExtensionsAwareBuilder.NodeGenerator) o;
                ng.write(writer);
            } else {
                throw logger.samlExtensionUnknownChild(o == null ? null : o.getClass());
            }
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    private void write(SubjectConfirmationType subjectConfirmationType) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION.get(),
                ASSERTION_NSURI.get());

        StaxUtil.writeAttribute(writer, JBossSAMLConstants.METHOD.get(), subjectConfirmationType.getMethod());

        BaseIDAbstractType baseID = subjectConfirmationType.getBaseID();
        if (baseID != null) {
            write(baseID);
        }
        NameIDType nameIDType = subjectConfirmationType.getNameID();
        if (nameIDType != null) {
            write(nameIDType, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
        }
        SubjectConfirmationDataType subjectConfirmationData = subjectConfirmationType.getSubjectConfirmationData();
        if (subjectConfirmationData != null) {
            write(subjectConfirmationData);
        }
        StaxUtil.writeEndElement(writer);
    }

    private void write(SubjectConfirmationDataType subjectConfirmationData) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION_DATA.get(),
                ASSERTION_NSURI.get());

        // Let us look at attributes
        String inResponseTo = subjectConfirmationData.getInResponseTo();
        if (StringUtil.isNotNull(inResponseTo)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo);
        }

        XMLGregorianCalendar notBefore = subjectConfirmationData.getNotBefore();
        if (notBefore != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(), notBefore.toString());
        }

        XMLGregorianCalendar notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
        if (notOnOrAfter != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), notOnOrAfter.toString());
        }

        String recipient = subjectConfirmationData.getRecipient();
        if (StringUtil.isNotNull(recipient)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.RECIPIENT.get(), recipient);
        }

        String address = subjectConfirmationData.getAddress();
        if (StringUtil.isNotNull(address)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.ADDRESS.get(), address);
        }

        if (subjectConfirmationData instanceof KeyInfoConfirmationDataType) {
            KeyInfoConfirmationDataType kicd = (KeyInfoConfirmationDataType) subjectConfirmationData;
            KeyInfoType keyInfo = (KeyInfoType) kicd.getAnyType();
            StaxWriterUtil.writeKeyInfo(writer, keyInfo);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    private void write(BaseIDAbstractType baseId) throws ProcessingException {
        throw logger.notImplementedYet("Method not implemented.");
    }
}