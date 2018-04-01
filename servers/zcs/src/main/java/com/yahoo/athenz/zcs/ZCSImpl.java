package com.yahoo.athenz.zcs;

import java.net.InetAddress;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.zcs.utils.ZCSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

/**
 * An implementation of ZCS.
 */
public class ZCSImpl implements Authorizer, KeyStore, ZCSHandler, ACSHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZCSImpl.class);

    private static String ROOT_DIR;
    
    public static Metric metric;
    public static String serverHostName  = null;

    protected Schema schema = null;
    protected PrivateKey privateKey = null;
    protected PrivateKeyStore privateKeyStore = null;
    protected String privateKeyId = "0";
    protected int principalCookieDefaultTimeout;
    protected Map<String, String> serverPublicKeyMap = null;
    protected AuditLogger auditLogger = null;
    protected String userDomain;
    protected String userDomainPrefix;
    protected String userDomainAlias;
    protected String userDomainAliasPrefix;
    protected Set<String> authFreeUriSet = null;
    protected List<Pattern> authFreeUriList = null;
    protected boolean secureRequestsOnly = true;
    protected int httpPort;
    protected int httpsPort;
    protected int statusPort;
    protected Status successServerStatus = null;
    
    private static final String TYPE_SERVICE_NAME = "ServiceName";

    protected Http.AuthorityList authorities = null;
    protected static Validator validator;
    
    public ZCSImpl() {

        // before doing anything else we need to load our
        // system properties from our config file
        
        loadSystemProperties();
        
        // let's first get our server hostname
        
        ZCSImpl.serverHostName = getServerHostName();
        
        // before we do anything we need to load our configuration
        // settings
        
        loadConfigurationSettings();
        
        // load our schema validator - we need this before we initialize
        // our store, if necessary
        
        loadSchemaValidator();
        
        // let's load our audit logger
        
        loadAuditLogger();
        
        // load any configured authorities to authenticate principals
        
        loadAuthorities();
        
        // we need a private key to sign any tokens and documents
        
        loadPrivateKeyStore();
        
        // check if we need to load any metric support for stats
        
        loadMetricObject();
        
        // retrieve our public keys
        
        loadServerPublicKeys();
        
        // make sure to set the keystore for any instance that requires it
        
        setAuthorityKeyStore();
    }

    void loadSystemProperties() {
        String propFile = System.getProperty(ZCSConsts.ZCS_PROP_FILE_NAME,
                getRootDir() + "/conf/ZCS_server/zcs.properties");
        ConfigProperties.loadProperties(propFile);
    }
    
    void setAuthorityKeyStore() {
        for (Authority authority : authorities.getAuthorities()) {
            if (AuthorityKeyStore.class.isInstance(authority)) {
                ((AuthorityKeyStore) authority).setKeyStore(this);
            }
        }
    }
    
    void loadSchemaValidator() {
        schema = ZCSSchema.instance();
        validator = new Validator(schema);
    }
    
    void loadConfigurationSettings() {

        secureRequestsOnly = Boolean.parseBoolean(
                System.getProperty(ZCSConsts.ZCS_PROP_SECURE_REQUESTS_ONLY, "true"));
 
        // retrieve the regular and status ports
        
        httpPort = ConfigProperties.getPortNumber(ZCSConsts.ZCS_PROP_HTTP_PORT,
                ZCSConsts.ZCS_HTTP_PORT_DEFAULT);
        httpsPort = ConfigProperties.getPortNumber(ZCSConsts.ZCS_PROP_HTTPS_PORT,
                ZCSConsts.ZCS_HTTPS_PORT_DEFAULT);
        statusPort = ConfigProperties.getPortNumber(ZCSConsts.ZCS_PROP_STATUS_PORT, 0);
        
        successServerStatus = new Status().setCode(ResourceException.OK).setMessage("OK");
        
        long timeout = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
        principalCookieDefaultTimeout = Integer.parseInt(
                System.getProperty(ZCSConsts.ZCS_PROP_PRINCIPAL_COOKIE_DEFAULT_TIMEOUT, Long.toString(timeout)));
        
        userDomain = System.getProperty(ZCSConsts.ZCS_PROP_USER_DOMAIN, ZCSConsts.ATHENZ_USER_DOMAIN);
        userDomainPrefix = userDomain + ".";
        
        userDomainAlias = System.getProperty(ZCSConsts.ZCS_PROP_USER_DOMAIN_ALIAS);
        if (userDomainAlias != null) {
            userDomainAliasPrefix = userDomainAlias + ".";
        }

        // get the list of uris that we want to allow an-authenticated access
        
        final String uriList = System.getProperty(ZCSConsts.ZCS_PROP_NOAUTH_URI_LIST);
        if (uriList != null) {
            authFreeUriSet = new HashSet<>();
            authFreeUriList = new ArrayList<>();
            String[] list = uriList.split(",");
            for (String uri : list) {
                if (uri.indexOf('+') != -1) {
                    authFreeUriList.add(Pattern.compile(uri));
                } else {
                    authFreeUriSet.add(uri);
                }
            }
        }
    }
    
    void loadMetricObject() {
        
        String metricFactoryClass = System.getProperty(ZCSConsts.ZCS_PROP_METRIC_FACTORY_CLASS,
                ZCSConsts.ZCS_METRIC_FACTORY_CLASS);
        MetricFactory metricFactory = null;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid MetricFactory class: " + metricFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid metric class");
        }
        
        // create our metric and increment our startup count
        
        ZCSImpl.metric = metricFactory.create();
        metric.increment("ZCS_sa_startup");
    }
    
    void loadPrivateKeyStore() {
        
        String pkeyFactoryClass = System.getProperty(ZCSConsts.ZCS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZCSConsts.ZCS_PRIVATE_KEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory = null;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        
        // extract the private key and public keys for our service
        
        StringBuilder privKeyId = new StringBuilder(256);
        privateKeyStore = pkeyFactory.create();
        
        // now that we have our keystore let's load our private key
        
        privateKey = privateKeyStore.getPrivateKey(ZCSConsts.ZCS_SERVICE, serverHostName, privKeyId);
        privateKeyId = privKeyId.toString();
    }
    
    void loadAuthorities() {
        
        // get our authorities
        
        String authListConfig = System.getProperty(ZCSConsts.ZCS_PROP_AUTHORITY_CLASSES,
                ZCSConsts.ZCS_PRINCIPAL_AUTHORITY_CLASS);
        authorities = new AuthorityList();

        String[] authorityList = authListConfig.split(",");
        for (int idx = 0; idx < authorityList.length; idx++) {
            Authority authority = getAuthority(authorityList[idx]);
            if (authority == null) {
                throw new IllegalArgumentException("Invalid authority");
            }
            authority.initialize();
            authorities.add(authority);
        }
    }
    
    void loadAuditLogger() {
        
        String auditFactoryClass = System.getProperty(ZCSConsts.ZCS_PROP_AUDIT_LOGGER_FACTORY_CLASS,
                ZCSConsts.ZCS_AUDIT_LOGGER_FACTORY_CLASS);
        AuditLoggerFactory auditLogFactory = null;
        
        try {
            auditLogFactory = (AuditLoggerFactory) Class.forName(auditFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid AuditLoggerFactory class: " + auditFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid audit logger class");
        }
        
        // create our audit logger
        
        auditLogger = auditLogFactory.create();
    }
    
    void loadServerPublicKeys() {
    }
    
    public static String getRootDir() {
        
        if (ROOT_DIR == null) {
            ROOT_DIR = System.getenv(ZCSConsts.ATHENZ_ENV_ROOT_DIR);
        }
        
        if (ROOT_DIR == null) {
            ROOT_DIR = ZCSConsts.ATHENZ_ROOT_DIR;
        }

        return ROOT_DIR;
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(ZCSConsts.ZCS_PROP_HOSTNAME);
        if (serverHostName == null || serverHostName.isEmpty()) {
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOGGER.info("Unable to determine local hostname: " + e.getMessage());
                serverHostName = "localhost";
            }
        }
        
        return serverHostName;
    }
    
    Authority getAuthority(String className) {
        
        LOGGER.debug("Loading authority {}...", className);
        
        Authority authority = null;
        try {
            authority = (Authority) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid Authority class: " + className + " error: " + e.getMessage());
            return null;
        }
        return authority;
    }

    void validateRequest(HttpServletRequest request, String caller) {
        validateRequest(request, caller, false);
    }
    
    void validateRequest(HttpServletRequest request, String caller, boolean statusRequest) {
        
        // first validate if we're required process this over TLS only
        
        if (secureRequestsOnly && !request.isSecure()) {
            throw requestError(caller + "request must be over TLS", caller,
                    ZCSConsts.ZCS_UNKNOWN_DOMAIN);
        }
        
        // second check if this is a status port so we can only
        // process on status requests
        
        if (statusPort > 0 && statusPort != httpPort && statusPort != httpsPort) {
            
            // non status requests must not take place on the status port
            
            if (!statusRequest && request.getLocalPort() == statusPort) {
                throw requestError("incorrect port number for a non-status request",
                        caller, ZCSConsts.ZCS_UNKNOWN_DOMAIN);
            }
            
            // status requests must not take place on a non-status port
            
            if (statusRequest && request.getLocalPort() != statusPort) {
                throw requestError("incorrect port number for a status request",
                        caller, ZCSConsts.ZCS_UNKNOWN_DOMAIN);
            }
        }
    }
    
    void validate(Object val, String type, String caller) {
        if (val == null) {
            throw requestError("Missing or malformed " + type, caller, ZCSConsts.ZCS_UNKNOWN_DOMAIN);
        }
        
        Result result = validator.validate(val, type);
        if (!result.valid) {
            throw requestError("Invalid " + type  + " error: " + result.error, caller,
                    ZCSConsts.ZCS_UNKNOWN_DOMAIN);
        }
    }
    
    void logPrincipal(ResourceContext ctx) {
        
        // we are going to log our principal and validate that it
        // contains expected data
        
        final Principal ctxPrincipal = ((RsrcCtxWrapper) ctx).principal();
        ((RsrcCtxWrapper) ctx).logPrincipal(ctxPrincipal);
        if (ctxPrincipal != null && ctxPrincipal.getFullName() != null) {
            validate(ctxPrincipal.getFullName(), TYPE_SERVICE_NAME, "logPrincipal");
        }
    }
    
    protected RuntimeException error(int code, String msg, String caller, String domainName) {
        
        LOGGER.error("Error: {} domain: {} code: {} message: {}", caller, domainName, code, msg);
        
        // emit our metrics if configured. the method will automatically
        // return from the caller if caller is null
        
        ZCSUtils.emitMonmetricError(code, caller, domainName, ZCSImpl.metric);
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    protected RuntimeException requestError(String msg, String caller, String domainName) {
        return error(ResourceException.BAD_REQUEST, msg, caller, domainName);
    }
    
    @Override
    public void getSamlLogin(ResourceContext context, String url, GetSamlLoginResult result) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void getSamlLogout(ResourceContext context, String url, GetSamlLogoutResult result) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void postAssertionConsumerService(ResourceContext context, String samlResponse, String relayState, HttpServletRequest request) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public Schema getRdlSchema(ResourceContext context) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Status getStatus(ResourceContext ctx) {
        // TODO Auto-generated method stub
        
        final String caller = "getstatus";
        metric.increment(ZCSConsts.HTTP_GET);
        logPrincipal(ctx);

        // validate our request as status request
        
        validateRequest(ctx.request(), caller, true);
        
        // create our timer object
        
        metric.increment(caller);
        Object timerMetric = metric.startTiming("getstatus_timing", null);
        
        metric.stopTiming(timerMetric);
        return successServerStatus;
    }

    @Override
    public ResourceContext newResourceContext(HttpServletRequest request, HttpServletResponse response) {
        // TODO Auto-generated method stub

        // check to see if we want to allow this URI to be available
        // with optional authentication support
        
        boolean optionalAuth = StringUtils.requestUriMatch(request.getRequestURI(),
                authFreeUriSet, authFreeUriList);
        return new RsrcCtxWrapper(request, response, authorities, optionalAuth, this);
    }


    @Override
    public String getPublicKey(String domain, String service, String keyId) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean access(String action, String resource, Principal principal, String trustDomain) {
        // TODO Auto-generated method stub
        return false;
    }
}
