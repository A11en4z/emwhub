package com.laigeoffer.pmhub.base.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 登录认证：只有登录之后才能进入该方法
 * 
 * @author canghe
 *
 */
// 元注解，用于描述注解的使用范围（即被描述的注解可以用在什么地方），runtime表示运行时有效
@Retention(RetentionPolicy.RUNTIME)
// 元注解，用于描述注解的作用目标（即被描述的注解可以用于什么地方），method表示方法，type表示类
@Target({ ElementType.METHOD, ElementType.TYPE })
// 定义自定义注解，仅用于标记方法，不包含任何属性
public @interface RequiresLogin
{
}
