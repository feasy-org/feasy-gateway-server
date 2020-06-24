package org.feasy.cloud.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * <p>
 *  网关启动类
 * </p>
 *
 * @author yangxiaohui
 * @since 2020/5/21
 */

@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = {"org.feasy.cloud"})
public class GatewayServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayServerApplication.class);
    }

}
