package com.yahoo.athenz.zcs.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.metrics.Metric;

public class ZCSUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZCSUtils.class);
    
    public static final boolean emitMonmetricError(int errorCode, String caller,
            String domainName, Metric metric) {

        if (errorCode < 1) {
            return false;
        }
        if (caller == null || caller.isEmpty()) {
            return false;
        }

        // Set 3 error metrics:
        // (1) cumulative "ERROR" (of all zcs request and error types)
        // (2) cumulative granular zcs request and error type (eg- "getsamllogin_error_400")
        // (3) cumulative error type (of all zcs requests) (eg- "error_404")
        String errCode = Integer.toString(errorCode);
        metric.increment("ERROR");
        if (domainName != null) {
            metric.increment(caller.toLowerCase() + "_error_" + errCode, domainName);
        } else {
            metric.increment(caller.toLowerCase() + "_error_" + errCode);
        }
        metric.increment("error_" + errCode);

        return true;
    }
}
