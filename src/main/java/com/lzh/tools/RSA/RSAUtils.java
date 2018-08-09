package com.lzh.tools.RSA;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class RSAUtils {

    /** *//**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /** *//**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /** *//**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /** *//**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /** *//**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /** *//**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /*
    * 获取公钥和私钥
    * */
    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /*
    * 对信息用自己的私钥生成签名信息
    * */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes =Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }

    /*
    * 签名验证--使用数据-公钥-签名信息
    * */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }

    /*
    * 解密私钥
    * */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        byte[] result = new byte[(encryptedData.length/128 + 1 )*117];
        int offSet = 0;
        byte[] cache;
        int i = 0;
        int len=0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
            for(byte b:cache){
                result[len++]=b;
            }
        }
        return result;
    }

    /*
    * 解密公钥
    * */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /*
    * 加密公钥
    * */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /*
    * 加密私钥
    * */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /*
    * 获取私钥
    * */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }

    /*
    * 获取公钥
    * */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }

    public static void main(String[] args) {
        try {
//            Map<String,Object> keyPair=genKeyPair();
//            System.out.println(getPrivateKey(keyPair));
//            System.out.println(getPublicKey(keyPair));
            /*
            * RAS签名+加密+解密
            * 客户端用自己的私钥对信息进行签名生成签名信息，对发送信息+签名信息使用服务端的公钥进行加密，发送
            * 服务端用自己的私钥解密，提取签名信息和具体信息加上客户端的公钥进行签名验证
            * */
            Map<String,Object> keyPair1=genKeyPair();
            Map<String,Object> keyPair2=genKeyPair();
            String msg="测试数据";
            System.out.println(msg);
            String sign=sign(msg.getBytes("UTF-8"),getPrivateKey(keyPair1));
            System.out.println(sign);
            String mas_sign=msg+sign;
            System.out.println(mas_sign);
            byte[] b1=encryptByPublicKey(mas_sign.getBytes("UTF-8"),getPublicKey(keyPair2));
            System.out.println(b1);
            String mas_sign2=new String(decryptByPrivateKey(b1,getPrivateKey(keyPair2)));
            System.out.println(mas_sign2);
            System.out.println(verify(msg.getBytes("UTF-8"),getPublicKey(keyPair1),sign));


//            String pwd="1";
//            //encode
//            byte[] b=encryptByPublicKey(pwd.getBytes("UTF-8"), "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqB0tXbjn+EMpmBwWOZtbT3oSEi30FHTEzMW9idXYSAnF8i5+4sCXmsvdxQJUIkIeU1IO4bzzhKIR64+A6kUB2jJYgYxijdWVKBrh944qPyzVBrMnpfyMrOGrctoZH626JIGXNvY3WL/5dOl48q1OgZEyIFhWxReaBqmc4fHAIMwIDAQAB");
//            String pwd_encoded=Base64.encodeBase64String(b);
//            //decode
//            System.out.println(pwd_encoded);
//            String pwd_decoded=new String(decryptByPrivateKey(Base64.decodeBase64(pwd_encoded), "MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAK9gDmrvnKrAi/4jwyIjoB6raIbG2/TPNS7huYdbkvGzCpkDVzcOMHL+ut6KubUntjipejzfK4bd/lV+8Mf/T+UZ/9g9vukIqEFQjJqZ8RcSWI3TVsfimrwkyzLbwzz9y4TcszDpJx+KN6O6mW+DoPLpn4lj+TQQ1dci12u8E6+1AgMBAAECgYEAkUVBTCVloi/TBtZ62jmmdiFIeXQaWYSWqloCg/RAGYRUwAD7ariPO4J0KsnBISVfFTqV7fxzIsma1xlKvHBprZ8g9CMr77EK8fYLCBTlXNZXKDJy2prvBC1UOufYTWZJZ4gIr7ef6lHTuPAHXs1MDWaT3oxAh+kwRgPzAIxUd3UCQQDZVWBY/txyqoxlBxyA+xivNVsLX8wrKeRR9ApCZCAdVF9sAGw0lXIAC2QYxKfbRW5MhRT5IsLqy6Ofmjuf9hJHAkEAzpOoR9EaCP1BBdlf3GU21wyDb2ndyYNXlqqfZDJSd7xgwupF6KL3QHA1EfknGY2lqH7BsoGT7/4aw4N8pf9QIwJBAIFZ/TQ6zD47H8BpkR97U1/Eo+GLLNtr3YahdxG4whxywTBot/48DFPWc8cCFN2+3z0P4EG/3L8eYM53X5F/RbUCQQC9m/ZoBNv6yEn4jm9YomZVuRyjFO8H2dB5cJ7gnvfnAzdlcRc90udTdCqiFqj24XbeU4qCyED7lacHMhclXlU1AkEAtJHqT4QX5wIaqLCbxq2IGUTh6bA3Y7CIBtw//L6W4GrWy/LXsUI4kpInC4o42CRjLUHc7MS0fq1rWKsJX7ljZA=="));
//            System.out.println(pwd_decoded.trim());
//
//            System.out.println(getPublicKey(genKeyPair()));
//            System.out.println(getPrivateKey(genKeyPair()));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}