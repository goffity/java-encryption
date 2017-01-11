package com.goffity.demo.encryption;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class RSAEncryptionTest {

    private static final String plaintext = "abcdefghijklmnopqrstuvwxyz | ABCDEFGHIJKLMNOPQRSTUVWXYZ | กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรลวศษสหฬอฮ | 1234567890!@#$%^&*()_+|}{\\";
    private RSAEncryption rsaEncryption;

    @Before
    public void setUp() throws Exception {
        rsaEncryption = new RSAEncryption();
        rsaEncryption.init();
    }

//    @After
//    public void tearDown() throws Exception {
//
//    }

    @Test
    public void testEncrypt() throws Exception {
        System.out.println("testEncrypt()");

        String encrypted = rsaEncryption.encrypt(plaintext);

        assertNotNull(encrypted);
        assertNotSame(plaintext, encrypted);

    }

    @Test
    public void testDecrypt() throws Exception {
        System.out.println("testDecrypt()");

        String encrypted = rsaEncryption.encrypt(plaintext);
        String decrypted = rsaEncryption.decrypt(encrypted);

        assertNotNull(encrypted);
        assertNotSame(plaintext, encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void generateKey() throws Exception {
        rsaEncryption.generateKey();

        assertTrue(rsaEncryption.isKeyExists());
    }

    @Test
    public void isKeyExists() throws Exception {
        rsaEncryption.generateKey();

        assertTrue(rsaEncryption.isKeyExists());
    }

//    @Test
//    public void readPublicKey() throws Exception {
//
//    }
//
//    @Test
//    public void readPrivateKey() throws Exception {
//
//    }

}