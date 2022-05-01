import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Scanner;

public class Metodos {
    public static Scanner scanner = new Scanner(System.in);
    public static void ejercicio1(){

        KeyPair keyPair = Cifrar.randomGenerate(1024);

        String texto = scanner.nextLine();

        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[] encriptado = Cifrar.encryptData(keyPair.getPublic(), bytes);
        byte[] desencriptado = Cifrar.decryptData(keyPair.getPrivate(), encriptado);

        String msg = new String(desencriptado, 0, desencriptado.length);

        System.out.println("Texto original: " + texto);
        System.out.println("Texto en byte: " + bytes);
        System.out.println("Byte encriptado: " + encriptado);
        System.out.println("Byte desencriptado: " + desencriptado);
        System.out.println();
        System.out.println("KeyPair Public: " + keyPair.getPublic());
        System.out.println("KeyPair Public Algoritmo: " + keyPair.getPublic().getAlgorithm());
        System.out.println("KeyPair Public Format: " + keyPair.getPublic().getFormat());
        System.out.println("KeyPair Public Encoded: " + keyPair.getPublic().getEncoded());
        System.out.println();
        System.out.println("KeyPair Private: " + keyPair.getPrivate());
        System.out.println("KeyPair Private Algoritmo: " + keyPair.getPrivate().getAlgorithm());
        System.out.println("KeyPair Private Format: " + keyPair.getPrivate().getFormat());
        System.out.println("KeyPair Private Encoded: " + keyPair.getPrivate().getEncoded());
        System.out.println();
        System.out.println("Texto final: " + msg);

    }

    public static void ejercicio1_2_1(){

        try {
            KeyStore keyStore = Cifrar.loadKeyStore("/home/usuario/keystore_eric.ks","eric123");

            System.out.println("Tipo de KeyStore: " + keyStore.getType());
            System.out.println("Tamaño de KeyStore: " + keyStore.size());
            System.out.println("Alies: ");

            Enumeration<String> alies = keyStore.aliases();

            while (alies.hasMoreElements()) {
                System.out.print("  " + alies.nextElement() + "");
                System.out.println();
            }

            Certificate certificate = keyStore.getCertificate(keyStore.aliases().nextElement());
            System.out.println("Certificado \"lamevaclaum9\": " + certificate);
            System.out.println("Algoritmo \"lamevaclaum9\": " + certificate.getPublicKey().getAlgorithm());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void ejercicio1_2_2(){

        SecretKey secretKey = Cifrar.SecretKey(192);

        try {
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("eric123".toCharArray());
            KeyStore keyStore = Cifrar.loadKeyStore("/home/usuario/keystore_eric.ks","eric123");
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            keyStore.setEntry("mykey",secretKeyEntry,protectionParameter);
            FileOutputStream fos = new FileOutputStream("/home/usuario/keystore_eric.ks");
            keyStore.store(fos,"eric123".toCharArray());
            fos.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void ejercicio1_3(){

        try {
            PublicKey publicKey = Cifrar.getPublicKey("/home/usuario/archivo");
            System.out.println(publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void ejercicio1_4(){

        try {
            KeyStore keyStore = Cifrar.loadKeyStore("/home/usuario/keystore_eric.ks","eric123");
            PublicKey publicKey = Cifrar.getPublicKey(keyStore,"lamevaclaum9","eric123");
            System.out.println(publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void ejercicio1_5(){

        KeyPair keyPair = Cifrar.randomGenerate(1024);
        String texto = "Hola!";
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[] signatura = Cifrar.signData(bytes, keyPair.getPrivate());
        System.out.println(signatura);

        System.out.println("ejercicio1_6");
        System.out.println(Cifrar.validateSignature(bytes,signatura,keyPair.getPublic()));

    }

    public static void ejercicio2_2(){

        KeyPair keyPair = Cifrar.randomGenerate(1024);
        String texto = "Hoola!";
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[][] encriptado = Cifrar.encryptWrappedData(bytes,keyPair.getPublic());
        byte[] desencriptado = Cifrar.decryptWrappedData(encriptado[0], keyPair.getPrivate(),encriptado[1]);

        String msg = new String(desencriptado);
        System.out.println("Texto origen: " + texto);
        System.out.println("Texto en byte: " + bytes);
        System.out.println("Texto encriptado: " + encriptado[0]);
        System.out.println("Clave encriptado: " + encriptado[1]);
        System.out.println("Texto decriptado: " + desencriptado);
        System.out.println("Texto final: " + msg);

    }
}