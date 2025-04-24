import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger modulus;
    private BigInteger privateKey;
    private BigInteger publicKey;

    public RSA(int bits) {
        generateKeys(bits);
    }

    public String encrypt(String message) {
        if (message.isEmpty()) {
            throw new IllegalArgumentException("Message is empty");
        }
        return (new BigInteger(message.getBytes())).modPow(publicKey, modulus).toString();
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    public String decrypt(String encryptedMessage) {
        if (encryptedMessage.isEmpty()) {
            throw new IllegalArgumentException("Message is empty");
        }
        return new String((new BigInteger(encryptedMessage)).modPow(privateKey, modulus).toByteArray());
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(privateKey, modulus);
    }

    public final void generateKeys(int bits) {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bits / 2, 100, random);
        BigInteger q = new BigInteger(bits / 2, 100, random);
        modulus = p.multiply(q);

        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        publicKey = BigInteger.valueOf(3L);
        while (phi.gcd(publicKey).intValue() > 1) {
            publicKey = publicKey.add(BigInteger.TWO);
        }

        privateKey = publicKey.modInverse(phi);
    }
}
