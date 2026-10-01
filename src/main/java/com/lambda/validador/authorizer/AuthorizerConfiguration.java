package com.lambda.validador.authorizer;

import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.lambda.validador.security.JwtValidationService;

@Configuration(proxyBeanMethods = false)
public class AuthorizerConfiguration {

    /**
     * El tipo generico explicito no es cosmetico: Spring Cloud Function deduce de
     * aqui los tipos de entrada y salida de la lambda. La funcion se invoca desde
     * AuthorizerHandler, no a traves del adaptador FunctionInvoker.
     */
    @Bean
    public Function<APIGatewayV2CustomAuthorizerEvent, AuthorizerResult> jwtAuthorizer(
            JwtValidationService validator) {
        return new JwtAuthorizerFunction(validator)::authorize;
    }
}
