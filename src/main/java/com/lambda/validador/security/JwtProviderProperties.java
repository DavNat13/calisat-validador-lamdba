package com.lambda.validador.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Lista de proveedores de identidad (OpenID Connect) que el backend acepta como
 * emisores de tokens. Cada proveedor tiene su propio conjunto de llaves publicas
 * (JWK Set) y sus valores de "iss" y "aud" admitidos.
 *
 * <p>Se configura en application.yaml bajo app.security.jwt.providers. Al
 * desplegar en Lambda, cada valor se puede sobreescribir por variable de
 * entorno: APP_SECURITY_JWT_PROVIDERS_0_JWKSETURI, _0_ISSUERS_0, _0_AUDIENCES_0,
 * etc.</p>
 */
@ConfigurationProperties(prefix = "app.security.jwt")
public class JwtProviderProperties {

    private List<Provider> providers = new ArrayList<>();

    public List<Provider> getProviders() {
        return providers;
    }

    public void setProviders(List<Provider> providers) {
        this.providers = providers;
    }

    public static class Provider {

        // Solo identifica al proveedor en los logs de arranque.
        private String name;

        // URL donde el proveedor publica sus llaves publicas (JWK Set).
        private String jwkSetUri;

        // Valores admitidos del claim "iss". Si el token trae otro, se rechaza.
        private List<String> issuers = new ArrayList<>();

        // Valores admitidos del claim "aud". Vacio = no se valida la audiencia.
        private List<String> audiences = new ArrayList<>();

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getJwkSetUri() {
            return jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }

        public List<String> getIssuers() {
            return issuers;
        }

        public void setIssuers(List<String> issuers) {
            this.issuers = issuers;
        }

        public List<String> getAudiences() {
            return audiences;
        }

        public void setAudiences(List<String> audiences) {
            this.audiences = audiences;
        }
    }
}
