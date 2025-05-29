package com.laigeoffer.pmhub.gateway.filter;

import com.laigeoffer.pmhub.base.core.config.redis.RedisService;
import com.laigeoffer.pmhub.base.core.constant.CacheConstants;
import com.laigeoffer.pmhub.base.core.constant.HttpStatus;
import com.laigeoffer.pmhub.base.core.constant.SecurityConstants;
import com.laigeoffer.pmhub.base.core.constant.TokenConstants;
import com.laigeoffer.pmhub.base.core.utils.JwtUtils;
import com.laigeoffer.pmhub.base.core.utils.ServletUtils;
import com.laigeoffer.pmhub.base.core.utils.StringUtils;
import com.laigeoffer.pmhub.gateway.config.properties.IgnoreWhiteProperties;
import io.jsonwebtoken.Claims;
import org.apache.poi.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * 网关鉴权
 *
 * @author canghe
 */
@Component
public class AuthFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private static final String BEGIN_VISIT_TIME = "begin_visit_time";//开始访问时间

    // 排除过滤的 uri 地址，nacos自行添加
    @Autowired
    private IgnoreWhiteProperties ignoreWhite;

    @Autowired
    private RedisService redisService;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // todo:完成核心函数filter

        // 1. 从exchange获取请求对象
        ServerHttpRequest request = exchange.getRequest();

        // 2. 白名单根据请求中的url，跳过不需要验证的路径
        String url = request.getURI().getPath(); // 需要一个string
        if (ignoreWhite.getWhites().contains(url)){
            return chain.filter(exchange);
        }

        // 3.获取并校验JWT Token
        String jwtToken = getToken(request);
        if (StringUtils.isEmpty(jwtToken)){ // 先检查是否为null再检查长度，相比jwtToken.isEmpty()更安全高效？
            return unauthorizedResponse(exchange, "令牌不能为空！");
        }
            // 调用JwtUtils的parseToken方法解析JWT Token，返回一个Claims对象，包含了用户的相关信息
        Claims claims = JwtUtils.parseToken(jwtToken);
        if (claims == null){
            return unauthorizedResponse(exchange, "令牌已过期或验证不正确！");
        }

        // 4. 获取用户标识，到redis查询是否存在该token（处于登录状态）
        String userKey = JwtUtils.getUserKey(claims);
        boolean isLogin = redisService.hasKey(getTokenKey(userKey));
        if (!isLogin){
            return unauthorizedResponse(exchange, "登录已过期！");
        }

        // 5. 从Claims对象中获取用户ID和用户名
        String userId = JwtUtils.getUserId(claims);
        String userName = JwtUtils.getUserName(claims);
        if (StringUtils.isEmpty(userId) || StringUtils.isEmpty(userName)){
            return unauthorizedResponse(exchange, "令牌验证失败，用户信息为空！");
        }

        // 6. 请求头追加用户信息
        // 获取请求头的Builder对象，用于修改请求头
        ServerHttpRequest.Builder mutate = request.mutate();
        // 设置用户信息到请求
        addHeader(mutate, SecurityConstants.USER_KEY, userKey);
        addHeader(mutate, SecurityConstants.DETAILS_USER_ID, userId);
        addHeader(mutate, SecurityConstants.DETAILS_USERNAME, userName);
        // 内部请求来源参数清除（防止网关携带内部请求标识，造成系统安全风险）
        removeHeader(mutate, SecurityConstants.FROM_SOURCE);

        // 7.统计接口耗时
        // 记录访问接口的开始时间
        exchange.getAttributes().put(BEGIN_VISIT_TIME, System.currentTimeMillis());
        // 计算接口总耗时
        // 请求继续正常传递给下一个过滤器，用.then等待下游服务处理完后递归回来，用异步任务结算接口访问耗时。
        return chain.filter(exchange).then(Mono.fromRunnable(()->{
            try {
                Long beginVisitTime = exchange.getAttribute(BEGIN_VISIT_TIME);
                if (beginVisitTime != null){
                    log.info("访问接口主机: " + exchange.getRequest().getURI().getHost());
                    log.info("访问接口端口: " + exchange.getRequest().getURI().getPort());
                    log.info("访问接口URL: " + exchange.getRequest().getURI().getPath());
                    log.info("访问接口URL参数: " + exchange.getRequest().getURI().getRawQuery());
                    log.info("访问接口时长: " + (System.currentTimeMillis() - beginVisitTime) + "ms");
                    log.info(" #######################DIVIDED############################");
                    System.out.println();
                }
            } catch (Exception e) {
                log.error("记录日志时发生异常", e);
            }
        }));
    }

    // 添加请求头
    private void addHeader(ServerHttpRequest.Builder mutate, String name, Object value) {
        if (value == null) {
            return;
        }
        String valueStr = value.toString();
        String valueEncode = ServletUtils.urlEncode(valueStr);
        mutate.header(name, valueEncode);
    }

    private void removeHeader(ServerHttpRequest.Builder mutate, String name) {
        mutate.headers(httpHeaders -> httpHeaders.remove(name)).build();
    }

    // 处理鉴权异常，记录错误日志，并返回一个未授权响应
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String msg) {
        log.error("[鉴权异常处理]请求路径:{}", exchange.getRequest().getPath());
        return ServletUtils.webFluxResponseWriter(exchange.getResponse(), msg, HttpStatus.UNAUTHORIZED);
    }

    /**
     * 获取缓存key
     */
    private String getTokenKey(String token) {
        return CacheConstants.LOGIN_TOKEN_KEY + token;
    }

    /**
     * 获取请求token
     */
    private String getToken(ServerHttpRequest request) {

        // 从请求头的Authorization字段中获取token
        String token = request.getHeaders().getFirst(TokenConstants.AUTHENTICATION);

        // 如果前端设置了令牌前缀（比如"Bearer "），则裁剪掉前缀
        if (StringUtils.isNotEmpty(token) && token.startsWith(TokenConstants.PREFIX)) {
            token = token.replaceFirst(TokenConstants.PREFIX, StringUtils.EMPTY);
        }
        return token;
    }

    @Override
    public int getOrder() {
        return -200;
    }




}