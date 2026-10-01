package com.lambda.validador;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.authorizer.AuthorizerResult;

import tools.jackson.databind.ObjectMapper;

/**
 * Fija el formato exacto de lo que se escribe en el stream de salida de la Lambda.
 *
 * <p>Es el contrato que hizo fallar la integracion: cuando la respuesta salia
 * envuelta en el sobre de proxy integration, API Gateway devolvia 500. Estos
 * tests miran los bytes, no el objeto, porque el fallo estaba en como se
 * serializaba, no en que se devolvia.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AuthorizerHandlerTest {

    @Autowired
    private ObjectMapper mapper;

    private String invocar(java.util.function.Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult> function)
            throws Exception {
        ByteArrayOutputStream salida = new ByteArrayOutputStream();
        new AuthorizerHandler(function, mapper).handleRequest(new ByteArrayInputStream(evento()), salida, null);
        return salida.toString(StandardCharsets.UTF_8);
    }

    private byte[] evento() {
        return ("{\"version\":\"2.0\",\"type\":\"REQUEST\","
                + "\"routeArn\":\"arn:aws:execute-api:us-east-1:123456789012:abcdef/test/GET/admin\","
                + "\"routeKey\":\"GET /admin\",\"rawPath\":\"/admin\","
                + "\"headers\":{\"authorization\":\"Bearer token-ficticio\"},"
                + "\"requestContext\":{\"stage\":\"test\"}}").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void escribeElJsonPlanoCuandoAutoriza() throws Exception {
        String respuesta = invocar(evento -> AuthorizerResult.allowed());

        assertThat(respuesta).isEqualTo("{\"isAuthorized\":true}");
    }

    @Test
    void escribeElJsonPlanoCuandoRechaza() throws Exception {
        String respuesta = invocar(evento -> AuthorizerResult.denied());

        assertThat(respuesta).isEqualTo("{\"isAuthorized\":false}");
    }

    /**
     * El evento de un authorizer trae "routeKey" y "version", que son las claves
     * que hacen que un adaptador de integracion lo tome por un evento de proxy y
     * lo envuelva. La respuesta no debe llevar ni un campo mas.
     */
    @Test
    void laRespuestaNoLlevaSobreDeProxyIntegration() throws Exception {
        String respuesta = invocar(evento -> AuthorizerResult.allowed());

        assertThat(respuesta)
                .doesNotContain("isBase64Encoded")
                .doesNotContain("statusCode")
                .doesNotContain("body")
                .doesNotContain("headers");
    }

    @Test
    void leeElEventoYLoPasaALaFuncion() throws Exception {
        ByteArrayOutputStream salida = new ByteArrayOutputStream();
        AuthorizerResult[] recibido = new AuthorizerResult[1];

        new AuthorizerHandler(evento -> {
            assertThat(evento.getVersion()).isEqualTo("2.0");
            assertThat(evento.getType()).isEqualTo("REQUEST");
            assertThat(evento.getRouteKey()).isEqualTo("GET /admin");
            assertThat(evento.getHeaders()).containsEntry("authorization", "Bearer token-ficticio");
            recibido[0] = AuthorizerResult.allowed();
            return recibido[0];
        }, mapper).handleRequest(new ByteArrayInputStream(evento()), salida, null);

        assertThat(salida.toString(StandardCharsets.UTF_8)).isEqualTo("{\"isAuthorized\":true}");
    }
}
