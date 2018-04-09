package com.github.alallk;

import com.github.alallk.exception.TOTPLength;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Date;

import static com.github.alallk.util.Constants.*;
import static com.github.alallk.util.Constants.ErrorMessages.*;

/**
 *  Based in official implementation on https://tools.ietf.org/html/rfc6238
 */
public class TOTP {

    private int timeStep = 30;          //Time window default
    private int totpLength = 6;         //TOTP Code length default

    public String getTOTPCode(String secretKey) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime();
        return generateTOTP(hexKey, hexTime, Integer.toString(totpLength));
    }

    public String getTOTPCode(String secretKey, Date date) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime(date);
        return generateTOTP(hexKey, hexTime, Integer.toString(totpLength));
    }

    public boolean isValidTOTPCode(String secretKey, String codeTOTP){
        return getTOTPCode(secretKey).equals(codeTOTP);
    }

    public String getTOTPCode256(String secretKey) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime();
        return generateTOTP256(hexKey, hexTime, Integer.toString(totpLength));
    }

    public String getTOTPCode256(String secretKey, Date date) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime(date);
        return generateTOTP256(hexKey, hexTime, Integer.toString(totpLength));
    }

    public boolean isValidTOTPCode256(String secretKey, String codeTOTP){
        return getTOTPCode256(secretKey).equals(codeTOTP);
    }

    public String getTOTPCode512(String secretKey) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime();
        return generateTOTP512(hexKey, hexTime, Integer.toString(totpLength));
    }

    public String getTOTPCode512(String secretKey, Date date) {
        String hexKey = getHexKey(secretKey);
        String hexTime = getHexTime(date);
        return generateTOTP512(hexKey, hexTime, Integer.toString(totpLength));
    }

    public boolean isValidTOTPCode512(String secretKey, String codeTOTP){
        return getTOTPCode512(secretKey).equals(codeTOTP);
    }

    /**
     * Generates a secret key to use as base in TOTP
     * @return Secret Key(String)
     */
    public String getRandomSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        String secretKey = base32.encodeToString(bytes);
        return secretKey.toUpperCase();
    }

    public int getTimeStep() {
        return timeStep;
    }

    public void setTimeStep(int timeStep) {
        this.timeStep = timeStep;
    }

    public int getTOTPLength() {
        return totpLength;
    }

    public void setTOTPLength(int totpLength) {
        if(totpLength > MAX_LENGTH_TOTP){
            throw new TOTPLength(MAXIMUM_LIMIT_EXCEEDED_TOTP);
        }
        if(totpLength < MIN_LENGTH_TOTP){
            throw new TOTPLength(MIN_LIMIT_NOT_REACHED_TOTP);
        }
        this.totpLength = totpLength;
    }

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256,
     *                             HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text: the message or text to be authenticated
     */
    private static byte[] hmacSha(String crypto, byte[] keyBytes,
                                  byte[] text){
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                    new SecretKeySpec(keyBytes, RAW);
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }


    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex: the HEX string
     *
     * @return : a byte array
     */
    private static byte[] hexStr2Bytes(String hex){
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger(TEN + hex,16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, ret, 0, ret.length);
        return ret;
    }

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };

    /**
     * This method generates a TOTP value for the given
     * set of parameters. HMAC_SHA_1
     *
     * @param key: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return : a numeric String in base 10
     */
    private String generateTOTP(String key,
                                      String time,
                                      String returnDigits){
        return generateTOTP(key, time, returnDigits, HMAC_SHA_1);
    }


    /**
     * This method generates a TOTP value for the given
     * set of parameters. Algorithm HMAC_SHA_256.
     *
     * @param key: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return : a numeric String in base 10
     */
    private String generateTOTP256(String key,
                                         String time,
                                         String returnDigits){
        return generateTOTP(key, time, returnDigits, HMAC_SHA_256);
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters. Algorithm HMAC_SHA_512.
     *
     * @param key: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return : a numeric String in base 10
     */
    private String generateTOTP512(String key,
                                         String time,
                                         String returnDigits){
        return generateTOTP(key, time, returnDigits, HMAC_SHA_512);
    }


    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param key: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto: the crypto function to use
     *
     * @return : a numeric String in base 10
     */
    private String generateTOTP(String key,
                                      String time,
                                      String returnDigits,
                                      String crypto){
        int codeDigits = Integer.parseInt(returnDigits);
        StringBuilder result;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        StringBuilder timeBuilder = new StringBuilder(time);
        while (timeBuilder.length() < 16 )
            timeBuilder.insert(0, ZERO);

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(timeBuilder.toString());
        byte[] k = hexStr2Bytes(key);

        byte[] hash = hmacSha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < codeDigits) {
            result.insert(0, ZERO);
        }
        return result.toString();
    }

    /**
     * Convert String to Hex
     * @param secretKey the shared secret
     * @return HEX of String
     */
    private String getHexKey(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        return new String(Hex.encodeHex(bytes));
    }

    private String getHexTime() {
        long time = (System.currentTimeMillis() / THOUSAND) / timeStep;
        return Long.toHexString(time);
    }

    private String getHexTime(Date date) {
        long time = (date.getTime() / THOUSAND) / timeStep;
        return Long.toHexString(time);
    }
}
