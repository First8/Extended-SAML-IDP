package nl.first8.keycloak.samlendpoint;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import nl.first8.keycloak.dom.saml.v2.metadata.AttributeConsumingService;
import nl.first8.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import java.io.*;
import java.util.List;
import java.util.logging.Logger;



public class SamlEndpointProvider implements RealmResourceProvider {
    private static final Logger logger = Logger.getLogger(SamlEndpointProvider.class.getName());


    public SamlEndpointProvider(KeycloakSession keycloakSession) {
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("/pages/{pageName}")
    @Produces("text/html; charset=utf-8")
    public String getPageContent(@PathParam("pageName") String pageName) throws IOException {
        String filePath = "saml-extended-frontend/pages/" + pageName + ".html";
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filePath)) {
            if (inputStream == null) {
                return "File not found: " + pageName;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder contentBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
            reader.close();

            return contentBuilder.toString();
        }

    }
    @POST
    @Path("/pages/data")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public List<AttributeConsumingService> setAttributes(List<AttributeConsumingService> attributeServices) {
        AttributeConsumingServiceType.setAttributeConsumingServices(attributeServices);
        logger.info("Services set successfully.");
        return attributeServices;
    }


    @GET
    @Path("images/{imageName}")
    @Produces("images/*")
    public Response getImage(@PathParam("imageName") String imageName) throws IOException {
        String filePath = "saml-extended-frontend/images/" + imageName;

        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filePath)) {
            if (inputStream != null) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                byte[] imageData = outputStream.toByteArray();

                return Response.ok(imageData).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("File not found: " + imageName).build();
            }
        }
    }
    @GET
    @Path("/js/{fileName}")
    @Produces("application/javascript; charset=utf-8")

    public String getJSContent(@PathParam("fileName") String fileName) throws IOException {
        String filePath = "saml-extended-frontend/js/" + fileName + ".js";

        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filePath)) {
            if (inputStream == null) {
                return "File not found: " + fileName;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder contentBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
            reader.close();

            return contentBuilder.toString();
        }

    }



    @Override
    public void close() {
    }

}

