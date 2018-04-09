package com.github.alallk;

import com.github.alallk.exception.TOTPLength;
import org.junit.Test;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static com.github.alallk.Constants.*;
import static com.github.alallk.util.Constants.ErrorMessages.*;
import static org.junit.Assert.*;

public class TOTPTest{

    private final TOTP totp = new TOTP();

    @Test
    public void getRandomSecretKey() {
        String secretKey = totp.getRandomSecretKey();
        assertFalse(secretKey.isEmpty());
    }

    @Test
    public void getTOTPCode() {
        String secretKey = totp.getRandomSecretKey();
        String codeTOTP = totp.getTOTPCode(secretKey);
        assertFalse(codeTOTP.isEmpty());
        assertEquals(codeTOTP.length(), totp.getTOTPLength());
    }

    @Test
    public void getTOTPCode256() {
        String secretKey = totp.getRandomSecretKey();
        String codeTOTP = totp.getTOTPCode256(secretKey);
        assertFalse(codeTOTP.isEmpty());
        assertEquals(codeTOTP.length(), totp.getTOTPLength());
    }

    @Test
    public void getTOTPCode512() {
        String secretKey = totp.getRandomSecretKey();
        String codeTOTP = totp.getTOTPCode512(secretKey);
        assertFalse(codeTOTP.isEmpty());
        assertEquals(codeTOTP.length(), totp.getTOTPLength());
    }

    @Test
    public void getTOTPCodeWithDate() {
        String codeTOTP;
        String codeTOTPCurrent;
        String secretKey = totp.getRandomSecretKey();

        LocalDateTime time = LocalDateTime.now();
        time = time.withSecond(ZERO);
        codeTOTP = totp.getTOTPCode(secretKey, getDate(time));

        int steps = totp.getTimeStep() - 1;

        for(int i = 1; i <= steps; i++){
            LocalDateTime timeTemp = time.plusSeconds(i);
            codeTOTPCurrent = totp.getTOTPCode(secretKey, getDate(timeTemp));
            assertEquals(codeTOTP, codeTOTPCurrent);
        }
        assertNotEquals(totp.getTOTPCode(secretKey, getDate(time.withSecond(totp.getTimeStep()))),codeTOTP);
    }

    @Test
    public void getTOTPCode256WithDate() {
        String codeTOTP;
        String codeTOTPCurrent;
        String secretKey = totp.getRandomSecretKey();

        LocalDateTime time = LocalDateTime.now();
        time = time.withSecond(ZERO);
        codeTOTP = totp.getTOTPCode256(secretKey, getDate(time));

        int steps = totp.getTimeStep() - 1;

        for(int i = 1; i <= steps; i++){
            LocalDateTime timeTemp = time.plusSeconds(i);
            codeTOTPCurrent = totp.getTOTPCode256(secretKey, getDate(timeTemp));
            assertEquals(codeTOTP, codeTOTPCurrent);
        }
        assertNotEquals(totp.getTOTPCode(secretKey, getDate(time.withSecond(totp.getTimeStep()))), codeTOTP);
    }

    @Test
    public void getTOTPCode512WithDate() {
        String codeTOTP;
        String codeTOTPCurrent;
        String secretKey = totp.getRandomSecretKey();

        LocalDateTime time = LocalDateTime.now();
        time = time.withSecond(ZERO);
        codeTOTP = totp.getTOTPCode512(secretKey, getDate(time));

        int steps = totp.getTimeStep() - 1;

        for(int i = 1; i <= steps; i++){
            LocalDateTime timeTemp = time.plusSeconds(i);
            codeTOTPCurrent = totp.getTOTPCode512(secretKey, getDate(timeTemp));
            assertEquals(codeTOTP, codeTOTPCurrent);
        }
        assertNotEquals(totp.getTOTPCode512(secretKey, getDate(time.withSecond(totp.getTimeStep()))), codeTOTP);
    }

    @Test
    public void isValidCodeAllTOTP() {
        String secretKey = totp.getRandomSecretKey();

        String codeTOTP = totp.getTOTPCode(secretKey);
        assertTrue(totp.isValidTOTPCode(secretKey, codeTOTP));

        String totpCode256 = totp.getTOTPCode256(secretKey);
        assertTrue(totp.isValidTOTPCode256(secretKey, totpCode256));

        String totpCode512 = totp.getTOTPCode512(secretKey);
        assertTrue(totp.isValidTOTPCode512(secretKey, totpCode512));

        try {
            TimeUnit.SECONDS.sleep(STEP_TIME);
            assertFalse(totp.isValidTOTPCode(secretKey, codeTOTP));
            assertFalse(totp.isValidTOTPCode256(secretKey, totpCode256));
            assertFalse(totp.isValidTOTPCode512(secretKey, totpCode512));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            fail(ex.getMessage());
        }
    }

    @Test
    public void properties(){
        assertEquals(totp.getTimeStep(), STEP_TIME);
        assertEquals(totp.getTOTPLength(), SIX);

        totp.setTimeStep(TEN);
        assertEquals(totp.getTimeStep(), TEN);

        try{
            totp.setTOTPLength(TEN);
        }catch (TOTPLength ex){
            assertEquals(ex.getMessage(), MAXIMUM_LIMIT_EXCEEDED_TOTP);
            assertEquals(totp.getTOTPLength(), SIX);
        }

        try{
            totp.setTOTPLength(ZERO);
        }catch (TOTPLength ex){
            assertEquals(ex.getMessage(), MIN_LIMIT_NOT_REACHED_TOTP);
            assertEquals(totp.getTOTPLength(), SIX);
        }

        totp.setTimeStep(STEP_TIME);
        totp.setTOTPLength(SIX);
        assertEquals(totp.getTimeStep(), STEP_TIME);
        assertEquals(totp.getTOTPLength(), SIX);
    }


    private Date getDate(LocalDateTime localDateTime){
        return Date.from(ZonedDateTime.of( localDateTime, ZoneId.systemDefault()).toInstant());
    }

}