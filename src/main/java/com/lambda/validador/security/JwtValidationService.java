package com.lambda.validador.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Valida el JWT de una peticion.
 *
 * <p>Un decoder por emisor y un decorador que enruta cada token al decoder de su
 * proveedor, de modo que conviven Microsoft Entra ID y AWS Cognito en el mismo
 * authorizer sin que uno pueda validar tokens del otro.</p>
 *
 * <p>Del token solo se comprueba que sea valido. No se extraen roles ni se
 * construye contexto porque el backend vuelve a validar el token y se ocupa de
 * la identidad: este authorizer solo decide si la peticion pasa o se bloquea.</p>
 */
public class JwtValidationService {

    private final JwtDecoder decoder;

    public JwtValidationService(MultiIssuerJwtDecoder decoder) {
        this.decoder = decoder;
    }

    /**
     * Construye el enrutador multi-emisor a partir de la configuracion. Se separa
     * del constructor para que las pruebas puedan inyectar decoders propios.
     */
    public static MultiIssuerJwtDecoder construirDecoder(JwtProviderProperties properties) {
        Map<String, JwtDecoder> decodersPorEmisor = new LinkedHashMap<>();

        for (JwtProviderProperties.Provider provider : properties.getProviders()) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder
                    .withJwkSetUri(provider.getJwkSetUri())
                    .build();

            // createDefault() valida las fechas (exp/nbf) y el "iss" se comprueba
            // aparte contra TODOS los declarados. No se encadenan varios
            // createDefaultWithIssuer porque DelegatingOAuth2TokenValidator exige
            // que pase la conjuncion de sus validadores: un provider con dos "iss"
            // admitidos rechazaria cualquier token, ya que el que no coincide falla.
            List<OAuth2TokenValidator<Jwt>> validadores = new ArrayList<>();
            validadores.add(JwtValidators.createDefault());
            validadores.add(issuerValidator(provider.getIssuers()));

            // Si no se declara audiencia, no se valida "aud" (comportamiento previo).
            if (!provider.getAudiences().isEmpty()) {
                validadores.add(audienceValidator(provider.getAudiences()));
            }
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validadores));

            for (String issuer : provider.getIssuers()) {
                decodersPorEmisor.put(issuer, decoder);
            }
        }

        return new MultiIssuerJwtDecoder(decodersPorEmisor);
    }

    /**
     * @throws org.springframework.security.oauth2.jwt.JwtException si la firma,
     *         el emisor, la audiencia o las fechas no son validas.
     */
    public Jwt validate(String token) {
        return decoder.decode(token);
    }

    /**
     * Acepta el token si su "iss" es alguno de los declarados para el provider.
     *
     * <p>La lectura es estricta a proposito y por el mismo motivo que en
     * MultiIssuerJwtDecoder: "iss" debe ser un texto, nunca una lista. Spring
     * Security no sabria interpretarlo y el token debe rechazarse antes.</p>
     */
    private static OAuth2TokenValidator<Jwt> issuerValidator(List<String> issuers) {
        return token -> {
            Object iss = token.getClaims().get("iss");
            if (iss instanceof String texto && issuers.contains(texto)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "El token no fue emitido por este proveedor. iss: " + iss,
                    null));
        };
    }

    /**
     * Un token solo sirve para este backend si identifica a este backend como su
     * destinatario. Evita que un token legitimo emitido para otra API se pueda
     * reutilizar aqui.
     *
     * <p>El claim no siempre se llama igual: Microsoft Entra ID y el ID token de
     * Cognito lo ponen en "aud", pero el ACCESS token de Cognito lo pone en
     * "client_id" (por diseno, para que un access token no se pueda usar donde se
     * espera un ID token). Por eso se aceptan los dos.</p>
     */
    private static OAuth2TokenValidator<Jwt> audienceValidator(List<String> audiences) {
        return token -> {
            List<String> aud = token.getClaimAsStringList("aud");
            List<String> clientId = token.getClaimAsStringList("client_id");

            boolean aceptada = contieneUno(aud, audiences) || contieneUno(clientId, audiences);

            if (aceptada) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "El token no fue emitido para este backend. aud: " + aud + ", client_id: " + clientId,
                    null));
        };
    }

    private static boolean contieneUno(List<String> valores, List<String> esperados) {
        return valores != null && valores.stream().anyMatch(esperados::contains);
    }
}
