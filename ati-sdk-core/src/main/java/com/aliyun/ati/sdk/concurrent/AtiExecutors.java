package com.aliyun.ati.sdk.concurrent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class AtiExecutors {

    private static final Logger LOGGER = LoggerFactory.getLogger(AtiExecutors.class);

    public static final int DEFAULT_POOL_SIZE = 10;
    public static final int DEFAULT_QUEUE_CAPACITY = 500;

    private static volatile ExecutorService sharedExecutor;
    private static final Object LOCK = new Object();

    private AtiExecutors() {
    }

    public static Executor sharedIoExecutor() {
        ExecutorService executor = sharedExecutor;
        if (executor == null) {
            synchronized (LOCK) {
                executor = sharedExecutor;
                if (executor == null) {
                    executor = newIoExecutor(DEFAULT_POOL_SIZE);
                    sharedExecutor = executor;
                    LOGGER.debug("Created shared ATI I/O executor with {} threads",
                        DEFAULT_POOL_SIZE);
                }
            }
        }
        return executor;
    }

    public static ExecutorService newIoExecutor(int poolSize) {
        return new ThreadPoolExecutor(
            poolSize, poolSize,
            60L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(DEFAULT_QUEUE_CAPACITY),
            new AtiThreadFactory(),
            (runnable, executor) -> {
                LOGGER.error("ATI IO executor rejected task: poolSize={}, active={}, "
                        + "queued={}/{}",
                    executor.getPoolSize(), executor.getActiveCount(),
                    executor.getQueue().size(), DEFAULT_QUEUE_CAPACITY);
                throw new RejectedExecutionException(
                    "ATI IO executor saturated (queue=" + executor.getQueue().size()
                    + "/" + DEFAULT_QUEUE_CAPACITY
                    + ", active=" + executor.getActiveCount() + ")");
            }
        );
    }

    public static ScheduledExecutorService newScheduledExecutor(int corePoolSize) {
        return Executors.newScheduledThreadPool(corePoolSize,
            new AtiThreadFactory("ati-scheduled"));
    }

    public static void shutdown() {
        synchronized (LOCK) {
            if (sharedExecutor != null) {
                LOGGER.debug("Shutting down shared ATI I/O executor");
                sharedExecutor.shutdown();
                try {
                    if (!sharedExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                        sharedExecutor.shutdownNow();
                        LOGGER.warn("Shared executor did not terminate gracefully, "
                            + "forced shutdown");
                    }
                } catch (InterruptedException e) {
                    sharedExecutor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                sharedExecutor = null;
            }
        }
    }

    public static boolean isInitialized() {
        return sharedExecutor != null;
    }

    private static class AtiThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;

        AtiThreadFactory() {
            this("ati-io");
        }

        AtiThreadFactory(String namePrefix) {
            this.namePrefix = namePrefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r,
                namePrefix + "-" + threadNumber.getAndIncrement());
            t.setDaemon(true);
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }
}
