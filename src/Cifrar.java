import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Cifrar {
    public static SecretKey SecretKey(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize / 8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static byte[] encryptData(PublicKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(PrivateKey sKey, byte[] data) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return decryptedData;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static PublicKey getPublicKey(String fitxer) throws Exception {
        File f = new File(fitxer);
        FileInputStream in = new FileInputStream(f);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
        PublicKey pk = certificate.getPublicKey();
        return pk;
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws Exception {
        Key key = ks.getKey(alias, pwMyKey.toCharArray());
        if (key instanceof PrivateKey) {
            Certificate cert = ks.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return publicKey;
        }
        return null;
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            //Generar una clave
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            // Medida de la clave
            kgen.init(128);
            // clave simetrica
            SecretKey sKey = kgen.generateKey();
            // algoritmo de clave simetrica
            Cipher cipher = Cipher.getInstance("AES");
            // modo encrypt de la clave simetrica
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            // texto cifrado
            byte[] encMsg = cipher.doFinal(data);
            // algoritmo de clave publica
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",  "SunJCE");
            // modo wrap con la clave publica
            cipher.init(Cipher.WRAP_MODE, pub);
            // clave simetrica wrap
            byte[] encKey = cipher.wrap(sKey);
            // [0] == dato cifrado
            // [1] == clave wrap
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }
    public static byte[] decryptWrappedData(byte[] encryptedMessage, PrivateKey privateKey,byte[] encryptedKey) {
        try {
            // algoritmo de clave privada
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",  "SunJCE");
            // modo unwrap con la clave privada
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            // clave cifrada unwrap
            Key symmetricKey = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            // algoritmo de clave simetrica
            cipher = Cipher.getInstance("AES");
            // modo decrypt con la clave simetrica
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            // retornar texto descifrado
            return cipher.doFinal(encryptedMessage);
        } catch (GeneralSecurityException exception) {
            exception.printStackTrace();
            return null;
        }
    }
}