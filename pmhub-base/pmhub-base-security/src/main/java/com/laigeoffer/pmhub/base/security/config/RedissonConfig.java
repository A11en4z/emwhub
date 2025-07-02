package com.laigeoffer.pmhub.base.security.config;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author canghe
 * @description RedissonConfig
 * @create 2024-06-18-16:36
 */
@Configuration
public class RedissonConfig {
    @Value("${spring.redis.host}")  // spring注解，从配置文件读取对应属性值注入到类成员变量
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Value("${spring.redis.password:}")  // 如果没有密码，默认值为空
    private String redisPassword;
    @Bean
    public RedissonClient redissonClient() {
        Config config = new Config();
        config.useSingleServer()
                .setAddress("redis://" + redisHost + ":" + redisPort) //设置redis服务地址
                .setPassword(redisPassword.isEmpty() ? null : redisPassword) // 设置密码
                .setDatabase(0); // 设置数据库编号

        return Redisson.create(config);
    }
}
