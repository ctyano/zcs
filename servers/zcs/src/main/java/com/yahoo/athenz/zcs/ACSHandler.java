package com.yahoo.athenz.zcs;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface ACSHandler {
    public void postAssertionConsumerService(ResourceContext context, String samlResponse, String relayState, HttpServletRequest request);
    public ResourceContext newResourceContext(HttpServletRequest request, HttpServletResponse response);
}
