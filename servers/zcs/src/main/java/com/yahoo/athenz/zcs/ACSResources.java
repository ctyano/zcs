package com.yahoo.athenz.zcs;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.inject.Inject;

@Path("/v1")
public class ACSResources {

    @POST
    @Path("/saml/acs")
    @Produces(MediaType.APPLICATION_XML)
    public void postAssertionConsumerService(@FormParam("SAMLResponse") String samlResponse, @FormParam("RelayState") String relayState) {
        try {
            ResourceContext context = this.delegate.newResourceContext(this.request, this.response);
            context.authenticate();
            this.delegate.postAssertionConsumerService(context, samlResponse, relayState, request);
        } catch (ResourceException e) {
            int code = e.getCode();
            switch (code) {
            case ResourceException.BAD_REQUEST:
                throw typedException(code, e, ResourceError.class);
            case ResourceException.FORBIDDEN:
                throw typedException(code, e, ResourceError.class);
            case ResourceException.TOO_MANY_REQUESTS:
                throw typedException(code, e, ResourceError.class);
            case ResourceException.UNAUTHORIZED:
                throw typedException(code, e, ResourceError.class);
            default:
                System.err.println("*** Warning: undeclared exception (" + code + ") for resource getSamlLogin");
                throw typedException(code, e, ResourceError.class);
            }
        }
    }


    WebApplicationException typedException(int code, ResourceException e, Class<?> eClass) {
        Object data = e.getData();
        Object entity = eClass.isInstance(data) ? data : null;
        if (entity != null) {
            return new WebApplicationException(Response.status(code).entity(entity).build());
        } else {
            return new WebApplicationException(code);
        }
    }

    @Inject private ACSHandler delegate;
    @Context private HttpServletRequest request;
    @Context private HttpServletResponse response;
    
}

