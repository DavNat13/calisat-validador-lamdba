package com.lambda.validador.support;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Genera un par de llaves RSA y firma tokens de prueba, de modo que los tests
 * ejerciten la validacion real de firma contra un JWK Set local en lugar de
 * simularla.
 *
 * <p>Nada de esto toca la red: las llaves se generan en memoria y el JWK Set se
 * publica en 127.0.0.1, de modo que la suite pasa sin conexion a internet y sin
 * depender de los proveedores reales (Entra ID ni Cognito).</p>
 */
public final class TestTokens {

    public static final String ISSUER = "https://login.example.com/tenant/v2.0";
    public static final String AUDIENCE = "api-client-id";
    public static final String OTRO_AUDIENCE = "otra-api";
    public static final String KEY_ID = "clave-de-prueba";

    private final RSAPrivateKey privateKey;
    private final RSAKey rsaKey;

    private TestTokens(KeyPair keyPair) {
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID(KEY_ID)
                .build();
    }

    public static TestTokens generar() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return new TestTokens(generator.generateKeyPair());
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo generar el par de llaves de prueba", e);
        }
    }

    /** Cuerpo de un JWK Set, igual en formato al que publican Entra ID y Cognito. */
    public String jwks() {
        return new JWKSet(rsaKey.toPublicJWK()).toString();
    }

    /** Publica el JWK Set generado en un servidor local de pruebas. */
    public static JwksServer publicarJwks(String jwksJson) {
        return JwksServer.publicar(jwksJson);
    }

    public String firmar(Map<String, Object> claims) {
        return firmar(ISSUER, AUDIENCE, claims, Instant.now().plusSeconds(3600));
    }

    public String firmarExpirado(Map<String, Object> claims) {
        return firmar(ISSUER, AUDIENCE, claims, Instant.now().minusSeconds(3600));
    }

    /** Issuer, audiencia y caducidad configurables, para probar los rechazos. */
    public String firmar(String issuer, String audience, Map<String, Object> claims, Instant expira) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(expira));

        if (issuer != null) {
            builder.issuer(issuer);
        }
        if (audience != null) {
            builder.audience(audience);
        }
        if (claims != null) {
            claims.forEach(builder::claim);
        }

        return serializar(builder.build());
    }

    /**
     * Algunas versiones de Nimbus entregan el claim "iss" como lista en lugar de
     * como texto, y el enrutador debe soportarlo.
     */
    public String firmarConIssEnLista(List<String> emisores) {
        return serializar(new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("iss", emisores)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build());
    }

    private String serializar(JWTClaimsSet claims) {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claims);

        try {
            jwt.sign(new RSASSASigner(privateKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("No se pudo firmar el token de prueba", e);
        }
        return jwt.serialize();
    }

    public static Map<String, Object> claims(Object... pares) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (int i = 0; i < pares.length; i += 2) {
            claims.put((String) pares[i], pares[i + 1]);
        }
        return claims;
    }
}
