package com.goffity.demo.encryption;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAEncryption {

    private static final String ALGORITHM = "RSA";

    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";

    private static Cipher cipher;


    public void init() throws NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
    }

    public String encrypt(String plaintext) throws Exception {
        System.out.println("encrypt()");

        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        PublicKey publicKey = (PublicKey) objectInputStream.readObject();

        return encrypt(plaintext, publicKey);
    }

    private String encrypt(String plaintext, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("encrypt()");

        System.out.println("key.getAlgorithm() " + key.getAlgorithm());
        System.out.println("key.getFormat() " + key.getFormat());

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = plaintext.getBytes("UTF-8");

        byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE);

        char[] encryptedTranspherable = Hex.encodeHex(encrypted);
        return new String(encryptedTranspherable);
    }

    public String decrypt(String encrypted) throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DecoderException {
        System.out.println("decrypt()");

        ObjectInputStream privateKeyObjectInputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        PrivateKey privateKey = (PrivateKey) privateKeyObjectInputStream.readObject();

        return decrypt(encrypted, privateKey);
    }

    private static String decrypt(String encrypted, PrivateKey key) throws InvalidKeyException, DecoderException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        System.out.println("decrypt()");
        cipher.init(Cipher.DECRYPT_MODE, key);

        System.out.println("key.getAlgorithm() " + key.getAlgorithm());
        System.out.println("key.getFormat() " + key.getFormat());

        byte[] bts = Hex.decodeHex(encrypted.toCharArray());

        byte[] decrypted = blockCipher(bts, Cipher.DECRYPT_MODE);

        return new String(decrypted, "UTF-8");
    }

    private static byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        byte[] scrambled;

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        for (int i = 0; i < bytes.length; i++) {

            // if we filled our buffer array we have our block ready for de- or encryption
            if ((i > 0) && (i % length == 0)) {
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn, scrambled);
                // here we calculate the length of the next buffer required
                int newlength = length;

                // if newlength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + length > bytes.length) {
                    newlength = bytes.length - i;
                }
                // clean the buffer array
                buffer = new byte[newlength];
            }
            // copy byte into our buffer.
            buffer[i % length] = bytes[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn, scrambled);

        return toReturn;
    }

    private static byte[] append(byte[] prefix, byte[] suffix) {
        byte[] toReturn = new byte[prefix.length + suffix.length];
        System.arraycopy(prefix, 0, toReturn, 0, prefix.length);
        System.arraycopy(suffix, 0, toReturn, prefix.length, suffix.length);
        return toReturn;
    }

    public void generateKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(1024);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);


        if (privateKeyFile.createNewFile()) {
            System.out.println("generate private key");
            ObjectOutputStream privateKeyFileOutputStream = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            privateKeyFileOutputStream.writeObject(keyPair.getPrivate());
            privateKeyFileOutputStream.flush();
            privateKeyFileOutputStream.close();
        }

        if (publicKeyFile.createNewFile()) {
            System.out.println("generate public key");
            ObjectOutputStream publicKeyFileOutputStream = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            publicKeyFileOutputStream.writeObject(keyPair.getPublic());
            publicKeyFileOutputStream.flush();
            publicKeyFileOutputStream.close();
        }
    }

    public boolean isKeyExists() {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        return privateKeyFile.exists() && publicKeyFile.exists();
    }

    private byte[] readFileBytes(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);
    }

    public PublicKey readPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("readPublicKey()");
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicSpec);
    }

    public PrivateKey readPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("readPrivateKey()");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
