package client;

import java.security.Key;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class SymetricCryptography {
	
	private static final String PADDING = "AES/ECB/PKCS5Padding";
	
	public static byte[] encrypt(Key pubkey, String text) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance(PADDING);
			rsa.init(Cipher.ENCRYPT_MODE, pubkey);
			byte[] bytes = DatatypeConverter.parseBase64Binary(text);
			return rsa.doFinal(bytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decrypt(Key decryptionKey, byte[] buffer) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance(PADDING);
			rsa.init(Cipher.DECRYPT_MODE, decryptionKey);
			byte[] bytes = rsa.doFinal(buffer);
			return bytes;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
