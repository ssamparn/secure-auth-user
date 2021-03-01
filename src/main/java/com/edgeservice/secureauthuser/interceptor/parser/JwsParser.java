package com.edgeservice.secureauthuser.interceptor.parser;

import com.edgeservice.secureauthuser.properties.JwsProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

@Slf4j
@RequiredArgsConstructor
public class JwsParser {

    private final JwsProperties jwsProperties;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public void initializeJwsProcessing() throws MalformedURLException {

        final DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(jwsProperties.getConnectionTimeout(), jwsProperties.getReadTimeout());

        final RemoteJWKSet<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwsProperties.getUrl()), resourceRetriever);

        final JWSVerificationKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS512, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);
    }

    public JWTClaimsSet parse(final String authUserHeader) throws JOSEException, BadJOSEException, ParseException {
        final JWTClaimsSet claimsSet = jwtProcessor.process(authUserHeader, null);
        log.debug("Received authenticated user: {}", claimsSet.toJSONObject());
        return claimsSet;
    }
}
