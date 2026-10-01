package com.lambda.validador;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Function;

import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.authorizer.AuthorizerResult;

import tools.jackson.databind.ObjectMapper;

/**
 * Handler de la Lambda authorizer.
 *
 * <p>Escribe en el stream de salida exactamente {"isAuthorized": true|false} y
 * nada mas, que es lo que un authorizer de HTTP API con
 * "EnableSimpleResponses: true" y payload 2.0 exige leer.</p>
 *
 * <p>No se usa el FunctionInvoker de Spring Cloud Function como handler a
 * proposito. Ese adaptador envuelve la respuesta en el sobre de proxy
 * integration ({isBase64Encoded, statusCode, body, headers}) siempre que el
 * evento de entrada tenga "httpMethod", o bien "routeKey" y "version". El evento
 * REQUEST de un authorizer de HTTP API trae siempre "routeKey" y "version", asi
 * que el envoltorio sale siempre, no hay propiedad para desactivarlo y el header
 * que lo controla se decide sobre el mensaje de entrada, antes de que corra la
 * funcion. El resultado era</p>
 *
 * <pre>
 * {"isBase64Encoded":false,"headers":{...},"body":"{\"isAuthorized\":false}","statusCode":200}
 * </pre>
 *
 * <p>API Gateway no encuentra "isAuthorized" en el nivel superior, no puede
 * interpretar la respuesta y contesta 500 Internal server error.</p>
 *
 * <p>Escribir la respuesta aqui evita depender de una convencion interna del
 * adaptador y deja el formato de salida a la vista.</p>
 */
public class AuthorizerHandler implements RequestStreamHandler {

    private final Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult> function;
    private final ObjectMapper mapper;

    /**
     * Arranque en frio. El runtime de Lambda crea una sola instancia por entorno
     * de ejecucion y la reutiliza en todas las invocaciones, asi que Spring
     * arranca una unica vez y la funcion se reutiliza caliente.
     */
    public AuthorizerHandler() {
        ConfigurableApplicationContext context = arrancar();
        this.function = context.getBean("jwtAuthorizer", Function.class);
        this.mapper = context.getBean(ObjectMapper.class);
    }

    AuthorizerHandler(Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult> function,
            ObjectMapper mapper) {
        this.function = function;
        this.mapper = mapper;
    }

    private static ConfigurableApplicationContext arrancar() {
        return SpringApplication.run(
                ValidadorApplication.class,
                "--spring.main.web-application-type=none",
                "--spring.cloud.function.web.export.enabled=false");
    }

    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {
        APIGatewayV2CustomAuthorizerEvent event = mapper.readValue(input, APIGatewayV2CustomAuthorizerEvent.class);

        output.write(mapper.writeValueAsBytes(function.apply(event)));
    }
}
