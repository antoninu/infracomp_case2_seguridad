package client;

import java.security.Key;

import javax.crypto.Mac;

public class HMACDigestCreator {

	public static byte[] getkeyedDigest(byte[] buffer, String hmacAlgorithm, Key symmetricKey){
		try{
			Mac hmac = Mac.getInstance(hmacAlgorithm);
			hmac.init(symmetricKey);
			byte[] digest = hmac.doFinal(buffer);
			return digest;

		} catch (Exception e){
			e.printStackTrace(); 
		}
		return null;
	}

}
