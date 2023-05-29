package icesi.security;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Security {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String KEY_ALGORITHM = "RSA";

    private static final int KEY_SIZE = 1024;

    private static final String PRIVATE_KEY_FILE = "privateKey";

    private static final String PUBLIC_KEY_FILE = "publicKey";

    private static final String MSG_DIGEST = "SHA-1";

    private static final String SALT = "SEGURIDAD";

    private static final String SECRET_KEY_ALGORITHM = "AES";

    private static final String AUTH_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";


    public SecretKey getKeyFromPassword(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(AUTH_KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, SALT.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_ALGORITHM);
        return secret;
    }
    public void keyGenerator(char[] pass) throws Exception {
        KeyPairGenerator keyPairGenerator = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Key publicKey = keyPair.getPublic();
            Key privateKey = keyPair.getPrivate();
            saveKey(publicKey, PUBLIC_KEY_FILE + ".key");
            saveKey(privateKey, PRIVATE_KEY_FILE + ".key");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        File inputFile = new File(PRIVATE_KEY_FILE + ".key");
        try {
            encryptFileWithKeys(getKeyFromPassword(pass), inputFile, new File(PRIVATE_KEY_FILE + ".cif"));
            inputFile.delete();
        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                 | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                 | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
    }

    public void saveKey(Key key, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            out.write(key.getEncoded());
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public IvParameterSpec generateIv() {

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public byte[] hashEncrypt(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(MSG_DIGEST);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                if (bytesRead > 0)
                    digest.update(buffer, 0, bytesRead);
            }
            return digest.digest();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void encryptFileWithKeys(SecretKey key, File inputFile, File outputFile)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec iv = generateIv();
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);
        byte[] hash = hashEncrypt(inputFile);
        fos.write(hash);
        byte[] ivB = iv.getIV();
        fos.write(ivB);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            fos.write(outputBytes);
        }
        fis.close();
        fos.close();
    }
}
