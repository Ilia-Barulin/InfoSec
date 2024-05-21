package org.example;

import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.io.*;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.PasswordProtection;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.FileInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;


public class SymmetricCrypto {

    // Method to generate SecureRandom instance with optional seed
    public static SecureRandom getSecureRandom(byte[] seed) {
        SecureRandom secureRandom;
        if (seed != null) {
            secureRandom = new SecureRandom(seed);
        } else {
            secureRandom = new SecureRandom();
        }
        return secureRandom;
    }


    public static SecretKey generateSecretKey(int keySize, SecureRandom secureRandom) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, secureRandom);
        return keyGen.generateKey();
    }

    public static String keyToHex(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static void displaySecretKey(SecretKey key) {
        String hexKey = keyToHex(key);
        System.out.println("Secret Key (Hex): " + hexKey);
    }

    public static void saveSecretKey(SecretKey key, String filename) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(key);
        }
    }

    public static SecretKey loadSecretKey(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (SecretKey) ois.readObject();
        }
    }


    public static void saveSecretKeyToKeystore(SecretKey key, String keystoreFilename, String alias, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(null, null);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.PasswordProtection keyStorePP = new KeyStore.PasswordProtection(password);
        keyStore.setEntry(alias, secretKeyEntry, keyStorePP);
        try (FileOutputStream fos = new FileOutputStream(keystoreFilename)) {
            keyStore.store(fos, password);
        }
    }

    public static SecretKey loadSecretKeyFromKeystore(String keystoreFilename, String alias, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(keystoreFilename)) {
            keyStore.load(fis, password);
        }
        return (SecretKey) keyStore.getKey(alias, password);
    }

    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted);
    }


    public static void displayEncryptedText(String encryptedText) {
        System.out.println("Encrypted Text (Hex): " + encryptedText);
    }


    public static void saveEncryptedText(String encryptedText, String filename) throws Exception {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(encryptedText);
        }
    }

    public static String loadEncryptedText(String filename) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            return reader.readLine();
        }
    }


}