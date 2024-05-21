package org.example;

import javax.crypto.SecretKey;
import java.util.Scanner;

import java.security.SecureRandom;
//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        SymmetricCrypto crypto = new SymmetricCrypto();

        try {
            SecretKey secretKey = null;
            while (true) {
                System.out.println("Choose an option:");
                System.out.println("1. Generate Secret Key");
                System.out.println("2. Load Secret Key from File");
                System.out.println("3. Load Secret Key from Keystore");
                System.out.println("4. Encrypt Text");
                System.out.println("5. Decrypt Text");
                System.out.println("6. Exit");
                int choice = scanner.nextInt();
                scanner.nextLine();  // consume newline



                switch (choice) {
                    case 1:
                        System.out.print("Enter key size (128, 192, 256): ");
                        int keySize = scanner.nextInt();
                        scanner.nextLine();  // consume newline
                        System.out.print("Enter seed (leave blank for default randomness): ");
                        String seedInput = scanner.nextLine();
                        SecureRandom secureRandom = seedInput.isEmpty() ?
                                SymmetricCrypto.getSecureRandom(null) :
                                SymmetricCrypto.getSecureRandom(seedInput.getBytes());
                        secretKey = crypto.generateSecretKey(keySize, secureRandom);
                        crypto.displaySecretKey(secretKey); // Displaying the key in hex format
                        System.out.print("Enter filename to save the key: ");
                        String filename = scanner.nextLine();
                        crypto.saveSecretKey(secretKey, filename);
                        break;
                    case 2:
                        System.out.print("Enter filename to load the key: ");
                        filename = scanner.nextLine();
                        secretKey = crypto.loadSecretKey(filename);
                        crypto.displaySecretKey(secretKey); // Displaying the loaded key in hex format
                        break;
                    case 3:
                        System.out.print("Enter keystore filename: ");
                        String keystoreFilename = scanner.nextLine();
                        System.out.print("Enter key alias: ");
                        String alias = scanner.nextLine();
                        System.out.print("Enter keystore password: ");
                        char[] password = scanner.nextLine().toCharArray();
                        secretKey = crypto.loadSecretKeyFromKeystore(keystoreFilename, alias, password);
                        crypto.displaySecretKey(secretKey); // Displaying the loaded key in hex format
                        break;
                    case 4:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter text to encrypt: ");
                        String plainText = scanner.nextLine();
                        System.out.print("Enter filename to save encrypted text: ");
                        filename = scanner.nextLine();
                        String encryptedText = crypto.encrypt(plainText, secretKey);
                        crypto.displayEncryptedText(encryptedText); // Displaying the encrypted text in hex format
                        crypto.saveEncryptedText(encryptedText, filename);
                        break;
                    case 5:
                        if (secretKey == null) {
                            System.out.println("No secret key loaded. Please generate or load a key first.");
                            break;
                        }
                        System.out.print("Enter filename to load encrypted text: ");
                        filename = scanner.nextLine();
                        encryptedText = crypto.loadEncryptedText(filename);
                        System.out.println("Decrypted Text: " + crypto.decrypt(encryptedText, secretKey));
                        break;
                    case 6:
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

