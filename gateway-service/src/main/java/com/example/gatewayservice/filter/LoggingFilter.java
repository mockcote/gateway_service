package com.example.gatewayservice.filter;

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

import java.nio.charset.StandardCharsets;

@Component
public class LoggingFilter implements GlobalFilter {
    private static final Logger log = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 요청 정보 로깅
        log.info("Request Path: {}", exchange.getRequest().getPath());
        log.info("HTTP Method: {}", exchange.getRequest().getMethod());
        log.info("Query Params: {}", exchange.getRequest().getQueryParams());
        log.info("Headers: {}", exchange.getRequest().getHeaders());

        // 요청 Body 처리
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    String body = StandardCharsets.UTF_8.decode(dataBuffer.asByteBuffer()).toString();
                    log.info("Request Body: {}", body);

                    // DataBuffer 복제
                    DataBuffer cachedBuffer = exchange.getResponse().bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));

                    // 기존 DataBuffer 해제
                    DataBufferUtils.release(dataBuffer);

                    // 새로운 ServerHttpRequest 생성
                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.just(cachedBuffer);
                        }
                    };

                    // 변환된 ServerWebExchange 생성
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(mutatedRequest)
                            .build();

                    return chain.filter(mutatedExchange);
                });
    }
}
