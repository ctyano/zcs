package com.yahoo.athenz.zcs;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RsrcCtxWrapper implements ResourceContext {
    
    private static final String ZCS_REQUEST_PRINCIPAL = "com.yahoo.athenz.auth.principal";

    com.yahoo.athenz.common.server.rest.ResourceContext ctx = null;
    boolean optionalAuth = false;

    public RsrcCtxWrapper(HttpServletRequest request, HttpServletResponse response, AuthorityList authorities,
            boolean optionalAuth, ZCSImpl zcsImpl) {
        // TODO Auto-generated constructor stub

        this.optionalAuth = optionalAuth;
        ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(request,
                response, authorities, zcsImpl);
    }

    public com.yahoo.athenz.common.server.rest.ResourceContext context() {
        return ctx;
    }

    public Principal principal() {
        return ctx.principal();
    }

    @Override
    public HttpServletRequest request() {
        return ctx.request();
    }

    @Override
    public HttpServletResponse response() {
        return ctx.response();
    }

    @Override
    public void authenticate() {
        try {
            ctx.authenticate();
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            
            // if this was an optional authentication request
            // then we'll skip the exception
            
            if (optionalAuth) {
                // TODO should add SAML login sequence here
                return;
            }
            throwZcsException(restExc);
        }
    }

    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            logPrincipal(ctx.principal());
            throwZcsException(restExc);
        }
    }

    public void logPrincipal(final Principal principal) {
        if (principal == null) {
            return;
        }
        logPrincipal(principal.getFullName());
    }
    
    public void logPrincipal(final String principal) {
        if (principal == null) {
            return;
        }
        ctx.request().setAttribute(ZCS_REQUEST_PRINCIPAL, principal);
    }
    
    public void throwZcsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {
        String msg = null;
        Object data = restExc.getData();
        if (data instanceof String) {
            msg = (String) data;
        }
        if (msg == null) {
            msg = restExc.getMessage();
        }
        throw new com.yahoo.athenz.zcs.ResourceException(restExc.getCode(),
                new ResourceError().code(restExc.getCode()).message(msg));
    }
}
