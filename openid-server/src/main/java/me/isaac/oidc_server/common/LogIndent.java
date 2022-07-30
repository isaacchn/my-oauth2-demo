package me.isaac.oidc_server.common;

import lombok.Getter;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class LogIndent {
    private Lock lock;
    @Getter
    private int indent = 0;

    private LogIndent() {
        lock = new ReentrantLock();
    }

    public void addIndent() {
        lock.lock();
        indent++;
        lock.unlock();
    }

    public void minusIndent() {
        lock.lock();
        indent--;
        lock.unlock();
    }

    private static class SingletonHolder {
        private static LogIndent INSTANCE = new LogIndent();
    }

    public static LogIndent getInstance() {
        return SingletonHolder.INSTANCE;
    }
}
