package com.yahoo.athenz.zcs;

import org.glassfish.hk2.utilities.binding.AbstractBinder;

public class ZCSBinder extends AbstractBinder  {

    @Override
    protected void configure() {
        ZCSImpl impl = new ZCSImpl();
        bind(impl).to(ZCSHandler.class);
        bind(impl).to(ACSHandler.class);
    }
}
