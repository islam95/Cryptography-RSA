package rsa;

/**
 * Class for encryption and decryption.
 *
 * @author Islam Dudaev
 * @since 27/03/2014
 */
// Perform a wide variety of input and output functions.
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
//////////////////////////////////////////////////////////////////////

// Perform calculations with arbitrarily high precision.
import java.math.BigInteger;
/////////////////////////////////////////////////////////////////////

// Enforce security restrictions.
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
//////////////////////////////////////////////////////////////////////

import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;

public class RSAEncryption {

    /**
     * String to hold name of the encryption algorithm.
     */
    public static final String RSA = "RSA";
    /**
     * The private key file.
     */
    public static final String PRIVATE_KEY = "Keys/private.key";
    /**
     * The public key file.
     */
    public static final String PUBLIC_KEY = "Keys/public.key";

    /**
     * Generate key which contains a pair of private and public key using 1024
     * bytes. Store the set of keys in Private.key and Public.key files.
     *
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static void generateKey() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(1024);
            final KeyPair key_pair = keyGen.generateKeyPair(); // just keypair holder

            File privateKey = new File(PRIVATE_KEY);
            File publicKey = new File(PUBLIC_KEY);

            if (privateKey.getParentFile() != null) {
                // creates parent directory for privatekey
                privateKey.getParentFile().mkdirs();
            }
            // creates the privatekey file in the directory
            privateKey.createNewFile();

            if (publicKey.getParentFile() != null) {
                publicKey.getParentFile().mkdirs();
            }
            // creates the publickey file in the directory
            publicKey.createNewFile();

            // Saving the Public key in a file
            ObjectOutputStream public_os = new ObjectOutputStream(
                    new FileOutputStream(publicKey));
            public_os.writeObject(key_pair.getPublic());
            public_os.close();

            // Saving the Private key in a file
            ObjectOutputStream private_os = new ObjectOutputStream(
                    new FileOutputStream(privateKey));
            private_os.writeObject(key_pair.getPrivate());
            private_os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * The method checks if the pair of public and private key has been
     * generated.
     *
     * @return flag indicating if the pair of keys were generated.
     */
    public static boolean areKeysPresent() {

        File privateKey = new File(PRIVATE_KEY);
        File publicKey = new File(PUBLIC_KEY);

        if (privateKey.exists() && publicKey.exists()) {
            return true;
        }
        return false;
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param plaintext: original plain text
     * @param publickey: Public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    public static String encrypt(String plaintext, PublicKey publickey) {
        String cipherText = "";
        try {
            // get an RSA cipher object with the provider
            Cipher cipher = Cipher.getInstance(RSA);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, publickey);
            // convert text into bytes "UTF-8" unicode
            byte[] bytes = plaintext.getBytes("UTF-8");
            // encrypt bytes
            byte[] encrypted = blocks(bytes, cipher, Cipher.ENCRYPT_MODE);
            // convert bytes into Hexadecimal
            cipherText = new BigInteger(1, encrypted).toString(16);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param encryptedtext: encrypted text
     * @param privatekey: Private key
     * @return plain text
     * @throws java.lang.Exception
     */
    public static String decrypt(String encryptedText, PrivateKey privatekey) {
        String original = "";
        try {
            // get an RSA cipher object and print the provider
            Cipher cipher = Cipher.getInstance(RSA);
            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, privatekey);
            // convert from hex into bytes
            byte[] fromHex = new BigInteger(encryptedText, 16).toByteArray();
            // decrypt 
            byte[] decrypted = blocks(fromHex, cipher, Cipher.DECRYPT_MODE);
            original = new String(decrypted, "UTF-8");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return original;
    }

    /**
     * Encrypting and decrypting blocks of bytes.
     *
     * @param bytes: byte array for encrypting or decrypting
     * @param mode: the mode for encryption or decryption
     * @return total: the final array of bytes
     * @throws IlligalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] blocks(byte[] bytes, Cipher cipher, int mode) {

        // this array holds intermediate results
        byte[] holdBytes = new byte[0];
        // this holds the total result
        byte[] total = new byte[0];
        // for encryption we use block of 100 bytes. 
        // for decryption - 128 bytes. because of RSA (1024/8 = 128)
        int size;
        if (mode == Cipher.ENCRYPT_MODE) {
            size = 110; // less than 117 bytes
        } else {
            size = 128;
        }
        // buffer to hold array of bytes to encrypt or decrypt
        byte[] buffer = new byte[size];
        try {
            for (int i = 0; i < bytes.length; i++) {
                // encrypting or decrypting blocks
                if ((i % size) == 0 && (i > 0)) { // if bytes reached 100 or 128
                    //encrypting data
                    holdBytes = cipher.doFinal(buffer);
                    // adding the result into total 
                    total = append(total, holdBytes);

                    int length = size;
                    // the remaining block of bytes
                    if (i + size > bytes.length) {
                        length = bytes.length - i;
                    }
                    // clear the buffer
                    buffer = new byte[length];
                }
                // copy bytes into buffer
                buffer[i % size] = bytes[i];
            }

            // encrypting remaining bytes in buffer when they are less than a block size
            holdBytes = cipher.doFinal(buffer);
            total = append(total, holdBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return total;
    }

    /**
     * The method appends byte arrays.
     *
     * @param first: first array of bytes
     * @param second: second array of bytes
     * @return total of two arrays
     */
    public static byte[] append(byte[] first, byte[] second) {
        // initialising new byte array with the length of both the first and second arrays
        byte[] total = new byte[first.length + second.length];
        // inserting first array into total
        for (int i = 0; i < first.length; i++) {
            total[i] = first[i];
        }
        // adding second array into total
        for (int i = 0; i < second.length; i++) {
            total[i + first.length] = second[i];
        }
        return total;
    }
}
