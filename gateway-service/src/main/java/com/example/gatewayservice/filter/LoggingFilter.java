package com.example.gatewayservice.filter;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class LoggingFilter implements GlobalFilter {
    private static final Logger log = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("Request Path: {}", exchange.getRequest().getPath());
        log.info("HTTP Method: {}", exchange.getRequest().getMethod());
        log.info("Query Params: {}", exchange.getRequest().getQueryParams());
        log.info("Headers: {}", exchange.getRequest().getHeaders());

        // ✅ GET 요청일 경우 Body를 읽지 않고 바로 체인 실행
        if (exchange.getRequest().getMethod().matches("GET")) {
            return chain.filter(exchange);
        }

        // 요청 Body 처리
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    String body = StandardCharsets.UTF_8.decode(dataBuffer.asByteBuffer()).toString();
                    log.info("Request Body: {}", body);

                    DataBuffer cachedBuffer = exchange.getResponse().bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
                    DataBufferUtils.release(dataBuffer);

                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.just(cachedBuffer);
                        }
                    };

                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                });
    }
}