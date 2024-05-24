package org.example;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.*;

public class DigitalSignatureCrypto {

    //  DSA key pair generation
    public static KeyPair generateKeyPair(int keySize, SecureRandom secureRandom) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(keySize, secureRandom);
        return keyGen.generateKeyPair();
    }

    // duh
    public static String keyToHex(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }


    public static void displayKey(Key key) {
        String hexKey = keyToHex(key);
        System.out.println("Key (Hex): " + hexKey);
    }


    public static void saveKeyToPEM(Key key, String filename) throws IOException {
        String type = key instanceof PrivateKey ? "PRIVATE" : "PUBLIC";
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        String pem = "-----BEGIN " + type + " KEY-----\n" + encoded + "\n-----END " + type + " KEY-----";
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(pem);
        }
    }


    public static PublicKey loadPublicKeyFromPEM(String filename) throws Exception {
        String pem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename)));
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePublic(keySpec);
    }


    public static PrivateKey loadPrivateKeyFromPEM(String filename) throws Exception {
        String pem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // signature Creation
    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }


    public static boolean verifySignature(String data, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        byte[] digitalSignature = Base64.getDecoder().decode(signatureStr);
        return signature.verify(digitalSignature);
    }


    public static void saveSignatureToFile(String signature, String filename) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(signature);
        }
    }


    public static String loadSignatureFromFile(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            return reader.readLine();
        }
    }
}