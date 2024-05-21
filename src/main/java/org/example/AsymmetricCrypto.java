package org.example;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import java.io.*;

public class AsymmetricCrypto {

    // Generate RSA key pair
    public static KeyPair generateKeyPair(int keySize, SecureRandom secureRandom) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, secureRandom);
        return keyGen.generateKeyPair();
    }

    // Convert key to hex format
    public static String keyToHex(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Display key in hex format
    public static void displayKey(Key key) {
        String hexKey = keyToHex(key);
        System.out.println("Key (Hex): " + hexKey);
    }

    // Save key to PEM format
    public static void saveKeyToPEM(Key key, String filename) throws IOException {
        String type = key instanceof PrivateKey ? "PRIVATE" : "PUBLIC";
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        String pem = "-----BEGIN " + type + " KEY-----\n" + encoded + "\n-----END " + type + " KEY-----";
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(pem);
        }
    }

    // Load public key from PEM format
    public static PublicKey loadPublicKeyFromPEM(String filename) throws Exception {
        String pem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename)));
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Load private key from PEM format
    public static PrivateKey loadPrivateKeyFromPEM(String filename) throws Exception {
        String pem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Encrypt data
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt data
    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted);
    }

    // Save encrypted text to file
    public static void saveEncryptedText(String encryptedText, String filename) throws Exception {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(encryptedText);
        }
    }

    // Load encrypted text from file
    public static String loadEncryptedText(String filename) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            return reader.readLine();
        }
    }
}
