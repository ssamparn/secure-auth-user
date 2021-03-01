package com.edgeservice.secureauthuser.config;

import com.edgeservice.secureauthuser.interceptor.parser.JwsParser;
import com.edgeservice.secureauthuser.properties.JwsProperties;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(JwsProperties.class)
public class JwsConfig {

    private final JwsProperties jwsProperties;
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    @Bean(initMethod = "initializeJwsProcessing")
    public JwsParser edgeRouterJwsParser() {
        jwtProcessor = new DefaultJWTProcessor<>();
        return new JwsParser(jwsProperties, jwtProcessor);
    }
}
