package com.yahoo.athenz.zcs;

import org.glassfish.jersey.server.ResourceConfig;

public class ZCS extends ResourceConfig {
    public ZCS() {
        registerClasses(ZCSResources.class, ACSResources.class);
        register(new ZCSBinder());
    }
}
