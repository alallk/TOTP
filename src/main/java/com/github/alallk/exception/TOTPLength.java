package com.github.alallk.exception;

public class TOTPLength extends RuntimeException {
    public TOTPLength() {
        super();
    }
    public TOTPLength(String s) {
        super(s);
    }
    public TOTPLength(String s, Throwable throwable) {
        super(s, throwable);
    }
    public TOTPLength(Throwable throwable) {
        super(throwable);
    }
}
