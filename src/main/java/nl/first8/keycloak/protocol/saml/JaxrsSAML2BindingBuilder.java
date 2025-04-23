package nl.first8.keycloak.protocol.saml;

import nl.first8.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.BaseSAML2BindingBuilder;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;

import javax.net.ssl.SSLContext;
import javax.ws.rs.core.*;
import javax.xml.XMLConstants;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class JaxrsSAML2BindingBuilder extends BaseSAML2BindingBuilder<JaxrsSAML2BindingBuilder> {
    protected static final Logger logger = Logger.getLogger(JaxrsSAML2BindingBuilder.class);

    public static final String KEYSTORE_ALIAS = "key";

    private final KeycloakSession session;
    private final SAMLIdentityProviderConfig config;

    public JaxrsSAML2BindingBuilder(KeycloakSession session, SAMLIdentityProviderConfig config) {
        this.session = session;
        this.config = config;
    }

    public SAMLIdentityProviderConfig getConfig() {
        return this.config;
    }

    public class PostBindingBuilder extends BasePostBindingBuilder {

        public PostBindingBuilder(BaseSAML2BindingBuilder builder, Document document) throws ProcessingException {
            super(builder, document);
        }

        public Response request(String actionUrl) throws ConfigurationException, ProcessingException, IOException {
            return createResponse(actionUrl, GeneralConstants.SAML_REQUEST_KEY);
        }

        public Response response(String actionUrl) throws ConfigurationException, ProcessingException, IOException {
            return createResponse(actionUrl, GeneralConstants.SAML_RESPONSE_KEY);
        }

        private Response createResponse(String actionUrl, String key) throws ProcessingException, ConfigurationException, IOException {
            MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
            formData.add(GeneralConstants.URL, actionUrl);
            formData.add(key, BaseSAML2BindingBuilder.getSAMLResponse(document));

            if (this.getRelayState() != null) {
                formData.add(GeneralConstants.RELAY_STATE, this.getRelayState());
            }

            return session.getProvider(LoginFormsProvider.class).setFormData(formData).createSamlPostForm();
        }

        public String artifactResolutionRequest(URI artifactResolutionEndpoint, RealmModel realm) throws IOException {
            logger.debugf("Sending artifact resolution request to %s", artifactResolutionEndpoint.toString());

            try {
                HttpClient httpClient = getHttpClient(realm);

                HttpPost post = createHttpPost(artifactResolutionEndpoint);
                HttpResponse httpResponse = httpClient.execute(post);

                return readHttpResponse(httpResponse, artifactResolutionEndpoint);
            } catch (GeneralSecurityException | SOAPException e) {
                logger.error("Error while getting ArtifactResponse. Returning empty response.", e);
            }
            return "";
        }

        private HttpClient getHttpClient(RealmModel realm) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
            if(getConfig().isMutualTLS()) {
                logger.debug("Mutual TLS is required creating custom HTTPClient");
                KeyWrapper rsaKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
                logger.tracef("Mutual TLS with Key ID: `%s`", rsaKey.getKid());
                char[] keyStorePassword = new char[0];

                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(null, null);
                keyStore.setCertificateEntry(rsaKey.getKid(), rsaKey.getCertificate());
                Certificate[] chain = {rsaKey.getCertificate()};
                keyStore.setKeyEntry(KEYSTORE_ALIAS, rsaKey.getPrivateKey(), keyStorePassword, chain);

                SSLContext sslContext = SSLContexts.custom()
                        .loadKeyMaterial(keyStore, keyStorePassword, (map, socket) -> "key")
                        .build();

                SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext,
                        new String[]{"TLSv1.3", "TLSv1.2", "TLSv1.1"},
                        null,
                        SSLConnectionSocketFactory.getDefaultHostnameVerifier());

                HttpClient httpClient = HttpClients.custom()
                        .setDefaultRequestConfig(RequestConfig.custom()
                                .setCookieSpec(CookieSpecs.STANDARD)
                                .build())
                        .setSSLSocketFactory(sslConnectionSocketFactory)
                        .build();

                return httpClient;
            }
            logger.debug("Mutual TLS is NOT required returning Keycloak default HTTPClient");
            return session.getProvider(HttpClientProvider.class).getHttpClient();
        }

        private HttpPost createHttpPost(URI artifactResolutionEndpoint) throws ProcessingException, ConfigurationException, SOAPException, IOException {
            HttpPost post = new HttpPost(artifactResolutionEndpoint);
            String entity = DocumentUtil.getDocumentAsString(document);

            if (getConfig().isArtifactResolutionSOAP()) {
                logger.debug("Put ArtifactResolve message in SOAP envelope.");
                entity = getSoapMessage(document);
            }
            if (getConfig().isArtifactResolutionWithXmlHeader()) {
                logger.debug("Adding xml header to ArtifactResolve message.");
                entity = "<?xml version=\"1.0\" encoding=\"" + getConfig().getCharSet().name() + "\"?>" + entity;
            }
            logger.tracef("Artifact Resolve message: %s", entity);
            post.setEntity(new StringEntity(entity));
            post.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_XML_TYPE.withCharset(getConfig().getCharSet().name()).toString());
            post.setHeader(HttpHeaders.ACCEPT, MediaType.TEXT_XML_TYPE.withCharset(getConfig().getCharSet().name()).toString());
            return post;
        }

        private String getSoapMessage(Document document) throws SOAPException, IOException {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            MessageFactory factory = MessageFactory.newInstance();
            SOAPMessage message = factory.createMessage();
            SOAPEnvelope envelope = message.getSOAPPart().getEnvelope();
            envelope.addNamespaceDeclaration("xsd", XMLConstants.W3C_XML_SCHEMA_NS_URI);
            envelope.addNamespaceDeclaration("xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
            message.getSOAPHeader().detachNode();
            message.getSOAPBody().addDocument(document);
            message.writeTo(bos);
            return bos.toString();
        }
    }

    private String readHttpResponse(HttpResponse httpResponse, URI artifactResolutionEndpoint) throws IOException, ProcessingException {
        boolean wasBase64 = false;

        int statusCode = httpResponse.getStatusLine().getStatusCode();
        logger.debugf("Response from endpoint (%s) was %s.", artifactResolutionEndpoint.toString(), statusCode);
        if (HttpStatus.SC_OK == statusCode) {
            InputStream content = httpResponse.getEntity().getContent();
            String response = new String(content.readAllBytes(), getConfig().getCharSet());
            logger.tracef("Response content: %s", response);

            if (isBase64String(response)) {
                wasBase64 = true;
                logger.debug("ArtifactResponse is Base64 encoded. Decoding response.");
                try (InputStream decodedStream = RedirectBindingUtil.base64DeflateDecode(response)) {
                    response = new String(decodedStream.readAllBytes());
                } catch (IOException e) {
                    logger.error("Error decoding Base64 response", e);
                }
            }


            if (getConfig().isArtifactResolutionWithXmlHeader()) {
                logger.debug("ArtifactResponse contains \"invalid\" XML header. Removing XML Header so we end up with valid message.");
                response = response.replaceAll("<\\?xml(.+)\\?>", "");
            }
            if (getConfig().isArtifactResolutionSOAP()) {
                logger.debug("ArtifactResponse in SOAP Envelope. Getting SOAP body.");
                try {
                    SOAPMessage soapResponse = MessageFactory
                            .newInstance()
                            .createMessage(null, new ByteArrayInputStream(response.getBytes(getConfig().getCharSet())));
                    Document document = soapResponse.getSOAPBody().extractContentAsDocument();
                    response = DocumentUtil.getDocumentAsString(document);
//                    response = response.replaceAll("ec:", "");
                } catch (ConfigurationException | SOAPException e) {
                    logger.warn("ArtifactResponse not a valid SOAP message; was expecting one, ignoring for now.");
                }
            }

            logger.tracef("ArtifactResponse only (plaintext): %s", response);

            if (wasBase64) {
                logger.debugf("ArtifactResponse is not Base64 encoded (anymore) will encode using CharSet: %s", config.getCharSet().name());
                response = RedirectBindingUtil.base64Encode(response.getBytes(getConfig().getCharSet()));
            }
            return response;
        } else {
            logger.warnf("Response from endpoint (%s) was not 200 but %s. Returning empty response.", artifactResolutionEndpoint.toString(), statusCode);
        }
        return "";


    }

    private boolean isBase64String(String response) {
        return response.matches("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
    }

    public static class RedirectBindingBuilder extends BaseRedirectBindingBuilder {
        public RedirectBindingBuilder(JaxrsSAML2BindingBuilder builder, Document document) throws ProcessingException {
            super(builder, document);
        }

        public Response response(String redirectUri) throws ProcessingException, ConfigurationException, IOException {
            return response(redirectUri, false);
        }

        public Response request(String redirect) throws ProcessingException, ConfigurationException, IOException {
            return response(redirect, true);
        }

        private Response response(String redirectUri, boolean asRequest) throws ProcessingException, ConfigurationException, IOException {
            URI uri = generateURI(redirectUri, asRequest);
            logger.tracef("redirect-binding uri: %s", uri);
            CacheControl cacheControl = new CacheControl();
            cacheControl.setNoCache(true);
            return Response.status(302).location(uri)
                    .header("Pragma", "no-cache")
                    .header("Cache-Control", "no-cache, no-store").build();
        }

    }

    @Override
    public JaxrsSAML2BindingBuilder.RedirectBindingBuilder redirectBinding(Document document) throws ProcessingException {
        return new JaxrsSAML2BindingBuilder.RedirectBindingBuilder(this, document);
    }

    @Override
    public JaxrsSAML2BindingBuilder.PostBindingBuilder postBinding(Document document) throws ProcessingException {
        return new JaxrsSAML2BindingBuilder.PostBindingBuilder(this, document);
    }
}
