## 1. DES - Symmetric Cipher

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class DESExample {
    public static void main(String[] args) throws Exception {
        String data = "HelloWorld";

        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
```


## 2. AES Algorithm

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESExample {
    public static void main(String[] args) throws Exception {
        String data = "SecureData";

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
```


## 3. Key Exchange (Diffie-Hellman)

```java
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;

public class KeyExchangeExample {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(512);
        KeyPair kp1 = kpg.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("DH");
        ka1.init(kp1.getPrivate());

        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhParamSpec = ((DHPublicKey) kp1.getPublic()).getParams();
        kpg2.initialize(dhParamSpec);
        KeyPair kp2 = kpg2.generateKeyPair();

        KeyAgreement ka2 = KeyAgreement.getInstance("DH");
        ka2.init(kp2.getPrivate());

        ka1.doPhase(kp2.getPublic(), true);
        ka2.doPhase(kp1.getPublic(), true);

        byte[] sharedSecret1 = ka1.generateSecret();
        byte[] sharedSecret2 = ka2.generateSecret();

        System.out.println(java.util.Arrays.equals(sharedSecret1, sharedSecret2) ?
                "Shared keys are equal" : "Keys are not equal");
    }
}
```


## 4. RSA (HTML + JavaScript)

```html
<!DOCTYPE html>
<html>
<head><title>RSA</title></head>
<body>
<script>
async function rsaDemo() {
    const key = await window.crypto.subtle.generateKey(
        {name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"},
        true,
        ["encrypt", "decrypt"]
    );

    const data = new TextEncoder().encode("Hello RSA!");
    const encrypted = await crypto.subtle.encrypt({name: "RSA-OAEP"}, key.publicKey, data);
    const decrypted = await crypto.subtle.decrypt({name: "RSA-OAEP"}, key.privateKey, encrypted);

    console.log("Encrypted:", new Uint8Array(encrypted));
    console.log("Decrypted:", new TextDecoder().decode(decrypted));
}
rsaDemo();
</script>
</body>
</html>
```


## 5. Digital Signature Algorithm

```java
import java.security.*;

public class DigitalSignatureExample {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature sign = Signature.getInstance("SHA1withDSA");
        sign.initSign(keyPair.getPrivate());
        sign.update("Message".getBytes());
        byte[] signature = sign.sign();

        sign.initVerify(keyPair.getPublic());
        sign.update("Message".getBytes());
        System.out.println("Verified: " + sign.verify(signature));
    }
}
```


## 6. Message Authentication Code (MAC)

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MACExample {
    public static void main(String[] args) throws Exception {
        String data = "MySecureMessage";
        String key = "SecretKey";

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKey);

        byte[] macBytes = mac.doFinal(data.getBytes());
        System.out.println("MAC: " + bytesToHex(macBytes));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
```


## 7. SHA-1 Digest

```java
import java.security.MessageDigest;

public class SHA1Example {
    public static void main(String[] args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update("Hello SHA-1".getBytes());
        byte[] digest = md.digest();

        for (byte b : digest) {
            System.out.printf("%02x", b);
        }
    }
}
```


## 8. VPN Connection Simulation

```java
public class VPNSetup {
    public static void main(String[] args) {
        System.out.println("Simulating VPN connection...");
        System.out.println("Authenticating...");
        System.out.println("Establishing secure tunnel...");
        System.out.println("VPN Connected Successfully.");
    }
}
```


## 9. MD5 Hash

```java
import java.security.MessageDigest;

public class MD5Example {
    public static void main(String[] args) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update("Hello MD5".getBytes());
        byte[] digest = md.digest();

        for (byte b : digest) {
            System.out.printf("%02x", b);
        }
    }
}
```


## 10. Dictionary Attack Protection

```java
import java.util.Scanner;

public class DictionaryAttackProtection {
    public static void main(String[] args) {
        String correctPassword = "Secure123";
        Scanner sc = new Scanner(System.in);
        int attempts = 3;

        while (attempts-- > 0) {
            System.out.print("Enter password: ");
            String input = sc.nextLine();
            if (input.equals(correctPassword)) {
                System.out.println("Access Granted.");
                return;
            } else {
                System.out.println("Incorrect. Attempts left: " + attempts);
            }
        }
        System.out.println("Account locked due to too many failed attempts.");
    }
}
```


## 11. Firewall Rule Setup

```java
public class FirewallRule {
    public static void main(String[] args) {
        String blockedIP = "192.168.1.100";
        String incomingIP = "192.168.1.100";

        if (incomingIP.equals(blockedIP)) {
            System.out.println("Access Denied: Firewall rule triggered.");
        } else {
            System.out.println("Access Allowed.");
        }
    }
}
```

