package org.feasy.cloud.gateway.conf;

import org.feasy.cloud.gateway.util.VerifyRequestUrlPermissionClient;
import org.feasy.cloud.permission.api.event.ServerApisAddListener;
import org.feasy.cloud.permission.api.event.ServerApisRemoveListener;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 *  自定义应用配置
 * </p>
 *
 * @author yangxiaohui
 * @since 2020/5/28
 */
@Slf4j
@Configuration
public class ApplicationConfiguration {
    /**
     * 服务API增加监听器配置
     */
    @Bean
    public ServerApisAddListener serverApisAddListener(VerifyRequestUrlPermissionClient verifyRequestUrlPermissionClient){
        return new ServerApisAddListener(verifyRequestUrlPermissionClient::addServerApis);
    }
    /**
     * 服务API删除监听器配置
     */
    @Bean
    public ServerApisRemoveListener serverApisRemoveListener(VerifyRequestUrlPermissionClient verifyRequestUrlPermissionClient){
        return new ServerApisRemoveListener(verifyRequestUrlPermissionClient::removeServerApis);
    }
}
