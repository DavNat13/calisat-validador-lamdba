package com.lambda.validador.security;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.nimbusds.jwt.SignedJWT;

/**
 * JwtDecoder que acepta tokens de varios proveedores de identidad a la vez
 * (Microsoft Entra ID y AWS Cognito).
 *
 * <p>Spring Security solo valida un "issuer-uri" por instancia, asi que aqui se
 * inspecciona el claim "iss" del token (SIN verificar la firma) unicamente para
 * elegir a que decoder se delega. Cada decoder delegado si valida firma,Audience,
 * fechas y su propio "iss", de modo que elegir el decoder por el "iss" no abre
 * la puerta a tokens de otro tenant: si el "iss" no esta en la lista, se rechaza.</p>
 */
public class MultiIssuerJwtDecoder implements JwtDecoder {

    private final Map<String, JwtDecoder> decodersPorEmisor;

    public MultiIssuerJwtDecoder(Map<String, JwtDecoder> decodersPorEmisor) {
        this.decodersPorEmisor = new LinkedHashMap<>(decodersPorEmisor);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        String emisor = leerEmisor(token);

        JwtDecoder decoder = decodersPorEmisor.get(emisor);
        if (decoder == null) {
            throw new JwtException("El token no fue emitido por un proveedor registrado. iss recibido: " + emisor);
        }

        return decoder.decode(token);
    }

    private String leerEmisor(String token) {
        Map<String, Object> claims;
        try {
            // Se lee el payload como JSON generico y no con getJWTClaimsSet():
            // este ultimo exige que "iss" sea un texto y lanza ParseException en
            // cuanto encuentra otro tipo.
            claims = SignedJWT.parse(token).getPayload().toJSONObject();
        } catch (ParseException e) {
            throw new JwtException("El token no es un JWT valido", e);
        }

        Object emisor = claims.get("iss");
        if (!(emisor instanceof String texto) || texto.isBlank()) {
            // La RFC 7519 obliga a que "iss" sea un texto. Aceptar una lista
            // ademas dejaria pasar al validador delegado un token que Spring
            // Security no sabe leer, asi que aqui se rechaza.
            throw new JwtException("El token no contiene un claim iss valido");
        }
        return texto;
    }
}
