package com.aliyun.ati.sdk.concurrent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class AtiExecutorsTest {

    @AfterEach
    void tearDown() {
        AtiExecutors.shutdown();
    }

    @Test
    void shouldLazilyInitializeSharedExecutor() {
        assertThat(AtiExecutors.isInitialized()).isFalse();

        Executor executor = AtiExecutors.sharedIoExecutor();

        assertThat(executor).isNotNull();
        assertThat(AtiExecutors.isInitialized()).isTrue();
    }

    @Test
    void shouldReturnSameSharedExecutor() {
        Executor first = AtiExecutors.sharedIoExecutor();
        Executor second = AtiExecutors.sharedIoExecutor();

        assertThat(first).isSameAs(second);
    }

    @Test
    void shouldCreateNewIoExecutor() {
        ExecutorService executor = AtiExecutors.newIoExecutor(2);
        assertThat(executor).isNotNull();
        executor.shutdown();
    }

    @Test
    void shouldExecuteTasksOnDaemonThreads() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        final boolean[] isDaemon = {false};
        final String[] threadName = {""};

        Executor executor = AtiExecutors.sharedIoExecutor();
        executor.execute(() -> {
            isDaemon[0] = Thread.currentThread().isDaemon();
            threadName[0] = Thread.currentThread().getName();
            latch.countDown();
        });

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(isDaemon[0]).isTrue();
        assertThat(threadName[0]).startsWith("ati-io-");
    }

    @Test
    void shouldShutdownAndResetState() {
        AtiExecutors.sharedIoExecutor();
        assertThat(AtiExecutors.isInitialized()).isTrue();

        AtiExecutors.shutdown();

        assertThat(AtiExecutors.isInitialized()).isFalse();
    }

    @Test
    void shouldRecreateAfterShutdown() {
        Executor first = AtiExecutors.sharedIoExecutor();
        AtiExecutors.shutdown();
        Executor second = AtiExecutors.sharedIoExecutor();

        assertThat(second).isNotSameAs(first);
    }
}
