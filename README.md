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
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SimpleAES {

    // Generate AES secret key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128
        return keyGen.generateKey();
    }

    // Encrypt a plain text using AES
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt an encrypted text using AES
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // Example usage
    public static void main(String[] args) {
        try {
            String plainText = "Hello, Symmetric World!";
            SecretKey secretKey = generateKey();

            String encrypted = encrypt(plainText, secretKey);
            String decrypted = decrypt(encrypted, secretKey);

            System.out.println("Original Text: " + plainText);
            System.out.println("Encrypted Text: " + encrypted);
            System.out.println("Decrypted Text: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```


## 3. Key Exchange (Diffie-Hellman)

```java
import java.util.*;
class DiffieHellmanAlgorithmExample {
    public static void main(String[] args) {
        long P, G, x, a, y, b, ka, kb;
        Scanner sc = new Scanner(System.in);
        System.out.println("Both the users should be agreed upon the public keys G and P");
        System.out.println("Enter value for public key G:");
        G = sc.nextLong();
        System.out.println("Enter value for public key P:");
        P = sc.nextLong();
        System.out.println("Enter value for private key a selected by user1:");
        a = sc.nextLong();
        System.out.println("Enter value for private key b selected by user2:");
        b = sc.nextLong();
        x = calculatePower(G, a, P);
        y = calculatePower(G, b, P);
        ka = calculatePower(y, a, P);
        kb = calculatePower(x, b, P);
        System.out.println("Secret key for User1 is:" + ka);
        System.out.println("Secret key for User2 is:" + kb);
    }
    private static long calculatePower(long x, long y, long P) {
        long result = 0;
        if (y == 1) {
            return x;
        } else {
            result = ((long)Math.pow(x, y)) % P;
            return result;
        }
    }
}

```


## 4. RSA (HTML + JavaScript)

```html

<html>

<head>
    <title>RSA Encryption</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
    <center>
        <h1>RSA Algorithm</h1>
        <h2>Implemented Using HTML & Javascript</h2>
        <hr>
        <table>
            <tr>
                <td>Enter First Prime Number:</td>
                <td>
                    <input type="number" value="53" id="p">
                </td>
            </tr>
            <tr>
                <td>Enter Second Prime Number:</td>
                <td>
                    <input type="number" value="59" id="q">
                    </p>
                </td>
            </tr>

            <tr>
                <td>Enter the Message(cipher text):
                    <br>[A=1, B=2,...]</td>
                <td>
                    <input type="number" value="89" id="msg">
                    </p>
                </td>
            </tr>
            <tr>
                <td>Public Key:</td>
                <td>
                    <p id="publickey"></p>
                </td>
            </tr>
            <tr>
                <td>Exponent:</td>
                <td>
                    <p id="exponent"></p>
                </td>
            </tr>
            <tr>
                <td>Private Key:</td>
                <td>
                    <p id="privatekey"></p>
                </td>
            </tr>
            <tr>
                <td>Cipher Text:</td>
                <td>
                    <p id="ciphertext"></p>
                </td>
            </tr>
            <tr>
                <td>
                    <button onclick="RSA();">Apply RSA</button>
                </td>
            </tr>
        </table>
    </center>

</body>
<script type="text/javascript">
    function RSA() {
    var gcd, p, q, no, n, t, e, i, x;
    gcd = function (a, b) { return (!b) ? a : gcd(b, a % b); };
    p = document.getElementById('p').value;
    q = document.getElementById('q').value;
    no = document.getElementById('msg').value;
    n = p * q;
    t = (p - 1) * (q - 1);
    for (e = 2; e < t; e++) {
    if (gcd(e, t) == 1) {
    break;
    }
    }
    for (i = 0; i < 10; i++) {
    x = 1 + i * t
    if (x % e == 0) {
    d = x / e;
    break;
    }
    }
    ctt = Math.pow(no, e).toFixed(0);
    ct = ctt % n;
    dtt = Math.pow(ct, d).toFixed(0);
    dt = dtt % n;
    document.getElementById('publickey').innerHTML = n;
    document.getElementById('exponent').innerHTML = e;
    document.getElementById('privatekey').innerHTML = d;
    document.getElementById('ciphertext').innerHTML = ct;
    }
</script>

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

