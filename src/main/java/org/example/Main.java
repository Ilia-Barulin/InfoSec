package org.example;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import java.security.SecureRandom;


public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto();
        DigitalSignatureCrypto digitalSignatureCrypto = new DigitalSignatureCrypto();


        SecretKey secretKey = null;
        KeyPair keyPair = null;

        try {
            while (true) {
                System.out.println("Choose the type of cryptography:");
                System.out.println("1. Symmetric");
                System.out.println("2. Asymmetric");
                System.out.println("3. Digital Signature");
                System.out.println("4. Exit");
                int choice = scanner.nextInt();
                scanner.nextLine();

                switch (choice) {
                    case 1:
                        symmetricMenu(scanner, symmetricCrypto);
                        break;
                    case 2:
                        asymmetricMenu(scanner, asymmetricCrypto);
                        break;
                    case 3:
                        digitalSignatureMenu(scanner, digitalSignatureCrypto);
                        break;
                    case 4:
                        System.exit(0);
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        scanner.close();
    }

    private static void symmetricMenu(Scanner scanner, SymmetricCrypto crypto) {
        SecretKey secretKey = null;
        while (true) {
            System.out.println("Choose an option:");
            System.out.println("1. Generate Secret Key");
            System.out.println("2. Load Secret Key from File");
            System.out.println("3. Save Secret Key to Keystore");
            System.out.println("4. Load Secret Key from Keystore");
            System.out.println("5. Encrypt Text");
            System.out.println("6. Decrypt Text");
            System.out.println("7. Back to Main Menu");
            int choice = scanner.nextInt();
            scanner.nextLine();

            try {
                switch (choice) {
                    case 1:
                        System.out.print("Enter key size (128, 192, 256): ");
                        int keySize = scanner.nextInt();
                        scanner.nextLine();
                        System.out.print("Enter seed (leave blank for default randomness): ");
                        String seedInput = scanner.nextLine();
                        SecureRandom secureRandom = seedInput.isEmpty() ?
                                SymmetricCrypto.getSecureRandom(null) :
                                SymmetricCrypto.getSecureRandom(seedInput.getBytes());
                        secretKey = crypto.generateSecretKey(keySize, secureRandom);
                        crypto.displaySecretKey(secretKey);
                        System.out.print("Enter filename to save the key: ");
                        String filename = scanner.nextLine();
                        crypto.saveSecretKey(secretKey, filename);
                        break;
                    case 2:
                        System.out.print("Enter filename to load the key: ");
                        filename = scanner.nextLine();
                        secretKey = crypto.loadSecretKey(filename);
                        crypto.displaySecretKey(secretKey);
                        break;
                    case 3:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter keystore filename: ");
                        String keystoreFilename = scanner.nextLine();
                        System.out.print("Enter key alias: ");
                        String alias = scanner.nextLine();
                        System.out.print("Enter keystore password: ");
                        char[] password = scanner.nextLine().toCharArray();
                        crypto.saveSecretKeyToKeystore(secretKey, keystoreFilename, alias, password);
                        System.out.println("Secret key saved to keystore.");
                        break;
                    case 4:
                        System.out.print("Enter keystore filename: ");
                        keystoreFilename = scanner.nextLine();
                        System.out.print("Enter key alias: ");
                        alias = scanner.nextLine();
                        System.out.print("Enter keystore password: ");
                        char[] passwordLoad = scanner.nextLine().toCharArray();
                        secretKey = crypto.loadSecretKeyFromKeystore(keystoreFilename, alias, passwordLoad);
                        crypto.displaySecretKey(secretKey);
                        break;
                    case 5:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter text to encrypt: ");
                        String plainText = scanner.nextLine();
                        System.out.print("Enter filename to save encrypted text: ");
                        filename = scanner.nextLine();
                        String encryptedText = crypto.encrypt(plainText, secretKey);
                        crypto.displayEncryptedText(encryptedText);
                        crypto.saveEncryptedText(encryptedText, filename);
                        break;
                    case 6:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename to load encrypted text: ");
                        filename = scanner.nextLine();
                        String encryptedTextToDecrypt = crypto.loadEncryptedText(filename);
                        System.out.println("Decrypted Text: " + crypto.decrypt(encryptedTextToDecrypt, secretKey));
                        break;
                    case 7:
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void asymmetricMenu(Scanner scanner, AsymmetricCrypto crypto) {
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        while (true) {
            System.out.println("Choose an option:");
            System.out.println("1. Generate Key Pair");
            System.out.println("2. Load Public Key from PEM");
            System.out.println("3. Load Private Key from PEM");
            System.out.println("4. Encrypt Text");
            System.out.println("5. Decrypt Text");
            System.out.println("6. Back to Main Menu");
            int choice = scanner.nextInt();
            scanner.nextLine();

            try {
                switch (choice) {
                    case 1:
                        System.out.print("Enter key size (e.g., 2048): ");
                        int keySize = scanner.nextInt();
                        scanner.nextLine();
                        System.out.print("Enter seed (leave blank for default randomness): ");
                        String seedInput = scanner.nextLine();
                        SecureRandom secureRandom = seedInput.isEmpty() ?
                                SymmetricCrypto.getSecureRandom(null) :
                                SymmetricCrypto.getSecureRandom(seedInput.getBytes());
                        KeyPair keyPair = crypto.generateKeyPair(keySize, secureRandom);
                        publicKey = keyPair.getPublic();
                        privateKey = keyPair.getPrivate();
                        crypto.displayKey(publicKey);
                        crypto.displayKey(privateKey);
                        System.out.print("Enter filename to save the public key: ");
                        String publicFilename = scanner.nextLine();
                        crypto.saveKeyToPEM(publicKey, publicFilename);
                        System.out.print("Enter filename to save the private key: ");
                        String privateFilename = scanner.nextLine();
                        crypto.saveKeyToPEM(privateKey, privateFilename);
                        break;
                    case 2:
                        System.out.print("Enter filename to load the public key: ");
                        publicFilename = scanner.nextLine();
                        publicKey = crypto.loadPublicKeyFromPEM(publicFilename);
                        crypto.displayKey(publicKey);
                        break;
                    case 3:
                        System.out.print("Enter filename to load the private key: ");
                        privateFilename = scanner.nextLine();
                        privateKey = crypto.loadPrivateKeyFromPEM(privateFilename);
                        crypto.displayKey(privateKey);
                        break;
                    case 4:
                        if (publicKey == null) {
                            System.out.println("No public key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter text to encrypt: ");
                        String plainText = scanner.nextLine();
                        System.out.print("Enter filename to save encrypted text: ");
                        String encryptedFilename = scanner.nextLine();
                        String encryptedText = crypto.encrypt(plainText, publicKey);
                        System.out.println("Encrypted Text (Hex): " + encryptedText);
                        crypto.saveEncryptedText(encryptedText, encryptedFilename);
                        break;
                    case 5:
                        if (privateKey == null) {
                            System.out.println("No private key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename to load encrypted text: ");
                        String encryptedTextFilename = scanner.nextLine();
                        String encryptedTextToDecrypt = crypto.loadEncryptedText(encryptedTextFilename);
                        System.out.println("Decrypted Text: " + crypto.decrypt(encryptedTextToDecrypt, privateKey));
                        break;
                    case 6:
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    private static void digitalSignatureMenu(Scanner scanner, DigitalSignatureCrypto crypto) {
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        while (true) {
            System.out.println("Choose an option:");
            System.out.println("1. Generate Key Pair");
            System.out.println("2. Load Public Key from PEM");
            System.out.println("3. Load Private Key from PEM");
            System.out.println("4. Sign Data");
            System.out.println("5. Verify Signature");
            System.out.println("6. Back to Main Menu");
            int choice = scanner.nextInt();
            scanner.nextLine();

            try {
                switch (choice) {
                    case 1:
                        System.out.print("Enter key size (e.g., 1024): ");
                        int keySize = scanner.nextInt();
                        scanner.nextLine();
                        System.out.print("Enter seed (leave blank for default randomness): ");
                        String seedInput = scanner.nextLine();
                        SecureRandom secureRandom = seedInput.isEmpty() ?
                                SymmetricCrypto.getSecureRandom(null) :
                                SymmetricCrypto.getSecureRandom(seedInput.getBytes());
                        KeyPair keyPair = crypto.generateKeyPair(keySize, secureRandom);
                        publicKey = keyPair.getPublic();
                        privateKey = keyPair.getPrivate();
                        crypto.displayKey(publicKey);
                        crypto.displayKey(privateKey);
                        System.out.print("Enter filename to save the public key: ");
                        String publicKeyFilename = scanner.nextLine();
                        crypto.saveKeyToPEM(publicKey, publicKeyFilename);
                        System.out.print("Enter filename to save the private key: ");
                        String privateKeyFilename = scanner.nextLine();
                        crypto.saveKeyToPEM(privateKey, privateKeyFilename);
                        break;
                    case 2:
                        System.out.print("Enter filename to load the public key: ");
                        String loadPublicFilename = scanner.nextLine();
                        publicKey = crypto.loadPublicKeyFromPEM(loadPublicFilename);
                        crypto.displayKey(publicKey);
                        break;
                    case 3:
                        System.out.print("Enter filename to load the private key: ");
                        String loadPrivateFilename = scanner.nextLine();
                        privateKey = crypto.loadPrivateKeyFromPEM(loadPrivateFilename);
                        crypto.displayKey(privateKey);
                        break;
                    case 4:
                        if (privateKey == null) {
                            System.out.println("No private key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename of the data to sign: ");
                        String dataFilename = scanner.nextLine();
                        String data = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dataFilename)));
                        String signature = crypto.signData(data, privateKey);
                        System.out.print("Enter filename to save the signature: ");
                        String signatureFilename = scanner.nextLine();
                        crypto.saveSignatureToFile(signature, signatureFilename);
                        System.out.println("Signature saved to " + signatureFilename);
                        break;
                    case 5:
                        if (publicKey == null) {
                            System.out.println("No public key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename of the data to verify: ");
                        dataFilename = scanner.nextLine();
                        data = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dataFilename)));
                        System.out.print("Enter filename of the signature: ");
                        signatureFilename = scanner.nextLine();
                        signature = crypto.loadSignatureFromFile(signatureFilename);
                        boolean isValid = crypto.verifySignature(data, signature, publicKey);
                        System.out.println("Signature is " + (isValid ? "valid" : "invalid"));
                        break;
                    case 6:
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


}


    // old one with just 1 selection for symmetric encryption
    /*
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        SymmetricCrypto crypto = new SymmetricCrypto();

        SecretKey secretKey = null;

        try {

            while (true) {
                System.out.println("Choose an option:");
                System.out.println("1. Generate Secret Key");
                System.out.println("2. Load Secret Key from File");
                System.out.println("3. Save Secret Key to Keystore");
                System.out.println("4. Load Secret Key from Keystore");
                System.out.println("5. Encrypt Text");
                System.out.println("6. Decrypt Text");
                System.out.println("7. Exit");
                int choice = scanner.nextInt();
                scanner.nextLine();



                switch (choice) {
                    case 1:
                        System.out.print("Enter key size (128, 192, 256): ");
                        int keySize = scanner.nextInt();
                        scanner.nextLine();
                        System.out.print("Enter seed (leave blank for default randomness): ");
                        String seedInput = scanner.nextLine();
                        SecureRandom secureRandom = seedInput.isEmpty() ?
                                SymmetricCrypto.getSecureRandom(null) :
                                SymmetricCrypto.getSecureRandom(seedInput.getBytes());
                        secretKey = crypto.generateSecretKey(keySize, secureRandom);
                        crypto.displaySecretKey(secretKey);
                        System.out.print("Enter filename to save the key: ");
                        String filename = scanner.nextLine();
                        crypto.saveSecretKey(secretKey, filename);
                        break;
                    case 2:
                        System.out.print("Enter filename to load the key: ");
                        filename = scanner.nextLine();
                        secretKey = crypto.loadSecretKey(filename);
                        crypto.displaySecretKey(secretKey);
                        break;
                    case 3:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter keystore filename: ");
                        String keystoreFilename = scanner.nextLine();
                        System.out.print("Enter key alias: ");
                        String alias = scanner.nextLine();
                        System.out.print("Enter keystore password: ");
                        char[] password = scanner.nextLine().toCharArray();
                        crypto.saveSecretKeyToKeystore(secretKey, keystoreFilename, alias, password);
                        System.out.println("Secret key saved to keystore.");
                        break;
                    case 4:
                        System.out.print("Enter keystore filename: ");
                        keystoreFilename = scanner.nextLine();
                        System.out.print("Enter key alias: ");
                        alias = scanner.nextLine();
                        System.out.print("Enter keystore password: ");
                        password = scanner.nextLine().toCharArray();
                        secretKey = crypto.loadSecretKeyFromKeystore(keystoreFilename, alias, password);
                        crypto.displaySecretKey(secretKey);
                        break;
                    case 5:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter text to encrypt: ");
                        String plainText = scanner.nextLine();
                        System.out.print("Enter filename to save encrypted text: ");
                        filename = scanner.nextLine();
                        String encryptedText = crypto.encrypt(plainText, secretKey);
                        crypto.displayEncryptedText(encryptedText);
                        crypto.saveEncryptedText(encryptedText, filename);
                        break;
                    case 6:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename to load encrypted text: ");
                        filename = scanner.nextLine();
                        encryptedText = crypto.loadEncryptedText(filename);
                        System.out.println("Decrypted Text: " + crypto.decrypt(encryptedText, secretKey));
                        break;
                    case 7:
                        System.exit(0);
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        scanner.close();
    }
}
    */



