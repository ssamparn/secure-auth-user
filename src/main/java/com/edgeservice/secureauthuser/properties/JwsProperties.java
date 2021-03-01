package com.edgeservice.secureauthuser.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties("security.jws")
public class JwsProperties {
    private String url;
    private int connectionTimeout;
    private int readTimeout;
}
