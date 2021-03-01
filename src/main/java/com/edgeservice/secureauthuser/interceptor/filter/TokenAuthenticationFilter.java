package com.edgeservice.secureauthuser.interceptor.filter;

import com.edgeservice.secureauthuser.exception.InvalidTokenException;
import com.edgeservice.secureauthuser.interceptor.parser.JwsParser;
import com.edgeservice.secureauthuser.interceptor.user.UserPrincipal;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;

@Slf4j
public class TokenAuthenticationFilter extends GenericFilterBean {

    public static final String AUTH_HEADER_NAME = "x-auth-user";

    private final ObjectMapper objectMapper;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final JwsParser jwsParser;

    public TokenAuthenticationFilter(final ObjectMapper objectMapper, AuthenticationEntryPoint authenticationEntryPoint, JwsParser jwsParser) {
        this.objectMapper = objectMapper;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwsParser = jwsParser;
    }

    @Override
    public void doFilter(final ServletRequest servletRequest,
                         final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {

        log.info("Applying token authentication filter for request" + ((HttpServletRequest) servletRequest).getPathInfo());

        try {
            final String encryptedToken = getEncryptedToken((HttpServletRequest) servletRequest);
            JWTClaimsSet jwtClaimsSet = jwsParser.parse(encryptedToken);
            final UserPrincipal userPrincipal = objectMapper.convertValue(jwtClaimsSet.getClaims(), UserPrincipal.class);
            SecurityContextHolder.getContext().setAuthentication(new TokenBasedAuthentication(encryptedToken, userPrincipal, new ArrayList<>()));
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (AuthenticationException | IllegalArgumentException | JsonProcessingException | ParseException | JOSEException | BadJOSEException e) {
            String msg = "Authentication Token provided has an invalid format and cannot be used. Issue: " + e.getClass().getSimpleName();
            log.error(msg, e);
            authenticationEntryPoint.commence((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse,
                    new InvalidTokenException(msg, e));
        }
    }

    private String getEncryptedToken(HttpServletRequest request) {
        String token = request.getHeader(AUTH_HEADER_NAME);
        if (token != null) {
            return token;
        }
        String msg = "The required HTTP header is missing: '" + AUTH_HEADER_NAME + "' must be populated in the request.";
        log.error(msg);
        throw new AuthenticationCredentialsNotFoundException(msg);
    }
}
