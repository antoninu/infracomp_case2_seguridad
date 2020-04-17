package client;

import java.security.Key;

import javax.crypto.Cipher;

public class AsymmetricCryprography {
	
	public static String ALGORITHM = "RSA";
	
	
	public static byte[] encrypt(Key pubkey, String text) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance(ALGORITHM);
			rsa.init(Cipher.ENCRYPT_MODE, pubkey);
			return rsa.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decrypt(Key decryptionKey, byte[] buffer) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance(ALGORITHM);
			rsa.init(Cipher.DECRYPT_MODE, decryptionKey);
			byte[] utf8 = rsa.doFinal(buffer);
			return utf8;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
