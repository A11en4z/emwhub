package com.laigeoffer.pmhub.base.security.pojo;

import com.laigeoffer.pmhub.base.security.service.redisson.IDistributedLock;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Objects;


@AllArgsConstructor
public class ILock implements AutoCloseable {
    /**
     * 持有的锁对象
     */
    @Getter
    private Object lock;
    /**
     * 分布式锁接口
     */
    @Getter
    private IDistributedLock distributedLock;

    @Override
    public void close() throws Exception {
        // 如果锁不为空，调用接口的unlock方法释放锁
        if (Objects.nonNull(lock)) {
            distributedLock.unLock(lock);
        }
    }
}
