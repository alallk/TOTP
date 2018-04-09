package com.github.alallk.util;

public class Constants {
    public static final int THOUSAND = 1000;
    public static final int MAX_LENGTH_TOTP = 8;
    public static final int MIN_LENGTH_TOTP = 1;
    public static final String RAW = "RAW";
    public static final String TEN = "10";
    public static final String ZERO = "0";
    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";
    public static final String HMAC_SHA_1 = "HmacSHA1";

    public static class ErrorMessages{
        public static final String MAXIMUM_LIMIT_EXCEEDED_TOTP = "Maximum limit exceeded";
        public static final String MIN_LIMIT_NOT_REACHED_TOTP = "Min limit not reached";

        private ErrorMessages() {}
    }

    private Constants() {}
}
