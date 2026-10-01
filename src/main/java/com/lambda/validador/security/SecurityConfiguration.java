package com.lambda.validador.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registra la cadena de validacion de tokens.
 *
 * <p>Ninguna de estas clases lleva esterotipo a proposito: JwtValidationService
 * necesita un JwtDecoder distinto en cada prueba, yMultiIssuerJwtDecoder es
 * apenas un contenedor de esos decoders. El cableado vive aqui para que ambas
 * cosas se puedan sustituir sin tocar las clases.</p>
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtProviderProperties.class)
public class SecurityConfiguration {

    /**
     * El decoder se construye a partir de la configuracion declarada en
     * application.yaml, no en el arranque de la Lambda. Asi una lista de
     * proveedores mal formada falla antes de la primera peticion, que es cuando
     * se la puede reportar.
     */
    @Bean
    public JwtValidationService jwtValidationService(JwtProviderProperties properties) {
        return new JwtValidationService(JwtValidationService.construirDecoder(properties));
    }
}
