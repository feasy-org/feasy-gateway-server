package org.feasy.cloud.gateway.filter;

import org.feasy.cloud.gateway.util.VerifyRequestUrlPermissionClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * <p>
 * 校验请求Token过滤器
 * </p>
 *
 * @author yangxiaohui
 * @since 2020/5/8
 */
@Slf4j
@Component
@RefreshScope
public class VerifyRequestTokenFilter implements GlobalFilter, Ordered {
    @Value("${system.request.ignore-token.urls}")
    private List<String> ignoreTokenUrls;

    private final VerifyRequestUrlPermissionClient verifyRequestUrlPermissionClient;

    public VerifyRequestTokenFilter(VerifyRequestUrlPermissionClient verifyRequestUrlPermissionClient) {
        this.verifyRequestUrlPermissionClient = verifyRequestUrlPermissionClient;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String url = exchange.getRequest().getURI().getPath();
        // 跳过swagger相关路径
        if (url.contains("api-docs") || url.contains("swagger") || url.contains("doc.html")) {
            return chain.filter(exchange);
        }
        // 跳过不需要验证的路径
        if (null != ignoreTokenUrls && ignoreTokenUrls.contains(url)) {
            return chain.filter(exchange);
        }
        return this.verifyRequestUrlPermissionClient.verifyRequest(exchange, chain);
    }

    @Override
    public int getOrder() {
        return -2147483600;
    }


}
