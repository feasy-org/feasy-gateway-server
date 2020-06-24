package org.feasy.cloud.gateway.util;

import com.alibaba.fastjson.JSONObject;
import org.feasy.cloud.author.dto.SmAccountToken;
import org.feasy.cloud.author.dto.SmUserToken;
import org.feasy.cloud.common.constant.Constant;
import org.feasy.cloud.common.result.ResultBuilder;
import org.feasy.cloud.common.result.ResultEnum;
import org.feasy.cloud.common.util.JwtTokenUtil;
import org.feasy.cloud.permission.api.entity.ServerApis;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * <p>
 * 校验权限工具类
 * </p>
 *
 * @author yangxiaohui
 * @since 2020/5/28
 */
@Slf4j
@Component
public class VerifyRequestUrlPermissionClient {
    private Map<String, List<String>> serverApisPermissionKeysMap = new ConcurrentHashMap<>();
    private Map<String, List<String>> pathValueServerApisPermissionKeysMap = new ConcurrentHashMap<>();

    private final RedisTemplate<String,Object> redisTemplate;
    public VerifyRequestUrlPermissionClient(RedisTemplate<String, Object> redisTemplate){
        this.redisTemplate = redisTemplate;
    }
    /**
     * 校验权限
     */
    public Mono<Void> verifyRequest(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 响应体
        ServerHttpResponse resp = exchange.getResponse();
        // 获取客户端类型
        String clientType = exchange.getRequest().getHeaders().getFirst(Constant.DEFAULT_REQUEST_CLIENT_TYPE_KEY);
        // 获取Token
        String token = exchange.getRequest().getHeaders().getFirst(Constant.DEFAULT_REQUEST_AUTHORIZATION_KEY);
        if (StringUtils.isBlank(token)) {
            // Token为空
            return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "请求无效！");
        }
        // 解析Token
        try {
            // 根据Client解析Token
            return this.parseTokenByClientType(token, clientType, exchange, chain);
        } catch (Exception e) {
            if (e instanceof MalformedJwtException) {
                log.error("非法Token：", e);
                return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "Token非法！");
            } else if (e instanceof ExpiredJwtException) {
                log.error("Token已过期：", e);
                return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "Token已过期！");
            }
            log.error("JWT解析失败：", e);
            return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "Token解析失败！");
        }
    }

    private Mono<Void> parseTokenByClientType(String token, String clientType, ServerWebExchange exchange, GatewayFilterChain chain) throws Exception {
        // 响应体
        ServerHttpResponse resp = exchange.getResponse();
        String url = exchange.getRequest().getURI().getPath();
        // 解析Token
        Claims claims = JwtTokenUtil.parseJWT(token);
        log.info("Jwt解析成功：{}", claims);
        Consumer<HttpHeaders> httpHeaders;
        // Header放入必要参数
        if (StringUtils.isBlank(clientType)) {
            // 匹配内存内的 Url 权限标识
            List<String> permissionKeys = this.getPermissionKeysByUrl(url);
            // 判断是否存在权限标识 如果该接口不存在或者权限标识不存在 直接放行
            if (permissionKeys != null && !permissionKeys.isEmpty()) {
                // 获取并 校验用户权限
                Object userObject = redisTemplate.opsForValue().get(Constant.REDIS_USER_TOKEN_KEY_PREFIX + token);
                if (userObject == null) {
                    return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "Token已过期！");
                }
                SmUserToken smUserToken = (SmUserToken) userObject;
                // 校验权限标识
                if (smUserToken.getPermissions() != null && !smUserToken.getPermissions().isEmpty()) {
                    if (!smUserToken.getPermissions().containsAll(permissionKeys)) {
                        return authErro(resp, ResultEnum.PERMISSION_DENIED, "无权访问！");
                    }
                }
            }
            httpHeaders = this.buildSmUserHeader(claims);
        }else if ("SDK".equals(clientType)) {
            // 校验请求域
            String requestSourceHostIp=exchange.getRequest().getRemoteAddress().getHostString();
            String requestSourceHostName=exchange.getRequest().getRemoteAddress().getHostName();
            // 校验请求接口权限
            Object accountTokenObject = redisTemplate.opsForValue().get(Constant.REDIS_ACCOUNT_TOKEN_KEY + token);
            if (accountTokenObject == null) {
                return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "Token已过期！");
            }
            SmAccountToken smAccountToken = (SmAccountToken) accountTokenObject;
            // 请求域
            if(!smAccountToken.getAccountScopeIps().contains(requestSourceHostIp)&&!smAccountToken.getAccountScopeIps().contains(requestSourceHostName)){
                return authErro(resp, ResultEnum.PERMISSION_DENIED, "CORS 请求被拒绝： 无效的域！");
            }
            if (!this.verifyAccountPermission(smAccountToken, url)) {
                return authErro(resp, ResultEnum.PERMISSION_DENIED, "无权访问！");
            }
            httpHeaders = this.buildSmAccountHeader(claims);
        } else {
            return authErro(resp, ResultEnum.AUTHORIZATION_INVALID, "无效的ClientType！");
        }
        // 修改RequestHeader 放入请求标识
        ServerHttpRequest serverHttpRequest = exchange.getRequest().mutate().headers(httpHeaders).build();
        exchange.mutate().request(serverHttpRequest).build();
        return chain.filter(exchange);
    }
    /**
     * 匹配Url获取该Url需要的权限标识
     */
    private List<String> getPermissionKeysByUrl(String url) {
        // 常规Url校验
        if (serverApisPermissionKeysMap.containsKey(url)) {
            return serverApisPermissionKeysMap.get(url);
        }
        return this.getPermissionKeysForPathValueApiByUrl(url);
    }

    /**
     * 从PathValueServerApi里查找匹配Url
     */
    private List<String> getPermissionKeysForPathValueApiByUrl(String url) {
        if (this.pathValueServerApisPermissionKeysMap != null && !this.pathValueServerApisPermissionKeysMap.isEmpty()) {
            for (Map.Entry<String, List<String>> entry : this.pathValueServerApisPermissionKeysMap.entrySet()) {
                if (Pattern.matches(this.buildPathValueApiRegx(entry.getKey()), url)) {
                    return entry.getValue();
                }
            }
        }
        return new ArrayList<>();
    }
    /**
     * 校验第三方账户接口权限
     */
    private boolean verifyAccountPermission(SmAccountToken smAccountToken, String requestUrl) {
        // 校验常规接口
        if (smAccountToken.getApiPath().contains(requestUrl)) {
            return true;
        }
        // 校验PathValue接口
        for (String pathValueUrl : smAccountToken.getPathValueApiPath()) {
            if (Pattern.matches(this.buildPathValueApiRegx(pathValueUrl), requestUrl)) {
                return true;
            }
        }
        return false;
    }
    private String buildPathValueApiRegx(String pathValueApiPath) {
        return Pattern.compile("\\{[\\w]*}").matcher(pathValueApiPath).replaceAll("[\\w]*");
    }

    /**
     * 生成用户的TokenHeader
     */
    private Consumer<HttpHeaders> buildSmUserHeader(Claims claims) {
        return httpHeader -> {
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_USER_ID_KEY, claims.get("id").toString());
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_USER_NAME_KEY, claims.get("userName").toString());
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_USER_PHONE_KEY, claims.get("userPhone").toString());
        };
    }

    /**
     * 生成第三方账户的TokenHeader
     */
    private Consumer<HttpHeaders> buildSmAccountHeader(Claims claims) {
        return httpHeader -> {
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_ACCOUNT_ID_KEY, claims.get("id").toString());
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_ACCOUNT_NAME_KEY, claims.get("accountName").toString());
            httpHeader.set(Constant.DEFAULT_REQUEST_TOKEN_ACCOUNT_SECRET_KEY_KEY, claims.get("secretKey").toString());
        };
    }
    /**
     * 构造授权失败信息
     */
    private Mono<Void> authErro(ServerHttpResponse resp, ResultEnum resultEnum, String mess) {
        resp.setStatusCode(HttpStatus.OK);
        resp.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        // 构造错误信息
        String returnStr = JSONObject.toJSONString(ResultBuilder.error(resultEnum, mess));
        DataBuffer buffer = resp.bufferFactory().wrap(returnStr.getBytes(StandardCharsets.UTF_8));
        return resp.writeWith(Flux.just(buffer));
    }


    /**
     * 添加数据
     */
    public void addServerApis(ServerApis serverApis) {
        serverApis.getApis().forEach(apiDetail -> {
            // 判断是否包含 PathValue参数
            if (Pattern.compile("\\w*/\\{\\w*}/\\w*").matcher(apiDetail.getApiPath()).find()) {
                this.pathValueServerApisPermissionKeysMap.put(
                        apiDetail.getApiPath(),
                        StringUtils.isBlank(apiDetail.getPermissionKeys()) ? new ArrayList<>() : Arrays.asList(apiDetail.getPermissionKeys().split(","))
                );
            } else {
                this.serverApisPermissionKeysMap.put(
                        apiDetail.getApiPath(),
                        StringUtils.isBlank(apiDetail.getPermissionKeys()) ? new ArrayList<>() : Arrays.asList(apiDetail.getPermissionKeys().split(","))
                );
            }
        });
    }

    /**
     * 删除服务API数据
     */
    public void removeServerApis(ServerApis serverApis) {
        serverApis.getApis().forEach(apiDetail -> {
            // 判断是否包含 PathValue参数
            if (Pattern.compile("\\w*/\\{\\w*}/\\w*").matcher(apiDetail.getApiPath()).find()) {
                this.pathValueServerApisPermissionKeysMap.remove(apiDetail.getApiPath());
            } else {
                this.serverApisPermissionKeysMap.remove(apiDetail.getApiPath());
            }
        });
    }
}
