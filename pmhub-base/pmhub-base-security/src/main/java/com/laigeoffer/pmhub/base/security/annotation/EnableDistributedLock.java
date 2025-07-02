package com.laigeoffer.pmhub.base.security.annotation;

import com.laigeoffer.pmhub.base.security.aspect.DistributedLockAspect;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * @author canghe
 * @description EnableDistributedLock 元注解，开启分布式锁功能
 * @create 2024-06-17-10:56
 */
@Target(ElementType.TYPE)  // 表示 EnableDistributedLock 注解只能应用于类、接口（包括注解类型）或者枚举类型。
@Retention(RetentionPolicy.RUNTIME) // 该注解在运行时可见，这样程序在运行时能通过反射机制获取注解信息。
@Documented  // 该注解会被包含在 JavaDoc 文档中
@Import({DistributedLockAspect.class}) // 自动注入DistributedLockAspect切面类到Spring容器中
public @interface EnableDistributedLock {
}
