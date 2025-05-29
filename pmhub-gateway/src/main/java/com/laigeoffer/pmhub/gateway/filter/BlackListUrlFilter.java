package com.laigeoffer.pmhub.gateway.filter;

import com.laigeoffer.pmhub.base.core.utils.ServletUtils;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 黑名单过滤器
 *
 * @author canghe
 */
// 组件注解
@Component
// 继承自 AbstractGatewayFilterFactory 类， 表示这是一个网关过滤器工厂类
// 泛型参数 Config 表示该工厂类的配置类
public class BlackListUrlFilter extends AbstractGatewayFilterFactory<BlackListUrlFilter.Config>
{
    // 重写 apply 方法，返回一个 GatewayFilter 对象
    @Override
    public GatewayFilter apply(Config config)
    {
        return (exchange, chain) -> {

            String url = exchange.getRequest().getURI().getPath();
            if (config.matchBlacklist(url))
            {
                return ServletUtils.webFluxResponseWriter(exchange.getResponse(), "请求地址不允许访问");
            }

            return chain.filter(exchange);
        };
    }
    // 调用父类 AbstractGatewayFilterFactory 的构造函数，传入配置类 Config 的 Class 对象
    public BlackListUrlFilter()
    {
        super(Config.class);
    }

    // 内部配置类
    public static class Config
    {
        // 存储黑名单URL的列表
        private List<String> blacklistUrl;

        // 存储黑名单URL的正则表达式列表
        private List<Pattern> blacklistUrlPattern = new ArrayList<>();

        // 检查传入的URL是否匹配黑名单中的任何一个URL
        public boolean matchBlacklist(String url)
        {
            return !blacklistUrlPattern.isEmpty() && blacklistUrlPattern.stream().anyMatch(p -> p.matcher(url).find());
        }

        public List<String> getBlacklistUrl()
        {
            return blacklistUrl;
        }

        public void setBlacklistUrl(List<String> blacklistUrl)
        {
            this.blacklistUrl = blacklistUrl;
            this.blacklistUrlPattern.clear();
            this.blacklistUrl.forEach(url -> {
                this.blacklistUrlPattern.add(Pattern.compile(url.replaceAll("\\*\\*", "(.*?)"), Pattern.CASE_INSENSITIVE));
            });
        }
    }

}
