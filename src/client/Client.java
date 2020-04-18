package client;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

public class Client {

	// protocol constants
	public static String HOLA = "HOLA";
	public static String OK = "OK";
	public static String ERROR = "ERROR";
	public static String ALGS = "AES";
	public static String ALGA = "RSA";
	public static String ALGD = "HMACMD5";
	public static String Padding = "AES/ECB/PKCS5Padding";
	public static String Encoding = "UTF-8";
	public static String BeginSendingCertificate = "CERTCLNT";
	public static String ESTADO = "ESTADO";
	public static String SEPARADOR = ":";
	public static String INICIO = "INICIO";
	public static String CERTSRV = "CERTSRV";
	private static final String initVector = "encryptionIntVec";

	Socket s;
	int safeServerPort = 4443;
	int unsafeServerPort = 4444;

	// sockets
	PrintWriter out;
	BufferedReader in;

	// IO variables
	OutputStream outStream;
	InputStream inputStream;

	// Key pairs
	KeyPair keyPair;

	PublicKey serverKey;

	// simmetric key
	SecretKey symmetricKey;

	// Server certificate
	X509Certificate serverCertificate;

	public Client() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGA);
			keyPair = generator.generateKeyPair();
			generator.initialize(1024);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	public void connect() {
		try {
			s = new Socket("localhost", safeServerPort);
			outStream = s.getOutputStream();
			out = new PrintWriter(outStream, true);
			out.println(HOLA);
			inputStream = s.getInputStream();
			in = new BufferedReader(new InputStreamReader(inputStream));
			String answer = in.readLine();
			if (answer.equals(OK)) {
				sendAlgotithms();
			} else {
				s.close();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void sendAlgotithms() {
		try {
			out.println("ALGORITMOS" + SEPARADOR + ALGS + SEPARADOR + ALGA + SEPARADOR
					+ ALGD);
			String answer = in.readLine();
			System.out.println(answer);
			if (answer.contains(ERROR)) {
				System.out.println("ERROR: communication stop");
				s.close();
			} else if (answer.equals(OK)) {
				sendCertificate();
			} else {
				s.close();
				throw new Exception("Unexpected answer from server");

			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void sendCertificate() {

		// we announce we will send the certificate
		//out.println(BeginSendingCertificate);


		try {
			X509Certificate certificate = CertificateBuilder
					.buildX509Certificate(keyPair);

			byte[] certAsBytes = certificate.getEncoded();
			String certificadoEnString = DatatypeConverter.printBase64Binary(certAsBytes);

			//s.getOutputStream().write(certAsBytes);
			//s.getOutputStream().flush();
			out.println(certificadoEnString);

			// checking if server validated the client certificate
			String validation = in.readLine();
			if (validation.equals(OK)) {
				receiveCertificate();
			} else {
				s.close();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void receiveCertificate() {
		out.println(OK);
		try {
			// reading line that announces the server will send its certificate
			String cert = in.readLine();
			System.out.println(cert.length());
			//out.println(OK);

				// check the quality of the certificate
				try {
					CertificateFactory certFactory = CertificateFactory
							.getInstance("X.509");
																														// certificate bytes
					//inputStream.read(serverCertificateInBytes);
					//InputStream in = new ByteArrayInputStream(serverCertificateInBytes);
					//InputStream targetStream = new ByteArrayInputStream(cert.getBytes());
					byte[] bytes = DatatypeConverter.parseBase64Binary(cert);
					//inputStream.read(bytes);
					InputStream in = new ByteArrayInputStream(bytes);
					serverCertificate = (X509Certificate) certFactory.generateCertificate(in);
					serverKey = serverCertificate.getPublicKey();
					System.out.println("holis");
					System.out.println(serverCertificate.getSigAlgName());

					out.println(OK);

				} catch (Exception e) {
					System.out.println(
							"Error in the received certificate. It cannot be decoded");
					e.printStackTrace();

				}
				//out.println(ESTADO + SEPARADOR + OK);

				receiveSimmetricKey();



		} catch (IOException e) {
			System.out.println(
					"Error reading line that announces the server will send its certificate");
		}

	}

	private void receiveSimmetricKey() {
		String llave;

		try {
			llave = in.readLine();
			System.out.println(llave);

			//String[] lineParts = line.split(":");
			byte[] bytes = DatatypeConverter.parseBase64Binary(llave);

			byte[] symmetricKeyArray = AsymmetricCryprography
					.decrypt(keyPair.getPrivate(), bytes);

			SecretKeySpec symmetricKey = new SecretKeySpec(symmetricKeyArray, ALGS);
			this.symmetricKey = symmetricKey;
			System.out.println("Symmetric key stablished in client " + symmetricKey.getEncoded());
			sendDecryptReto();

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void sendDecryptReto() {

		try {
			String reto = in.readLine();
			System.out.println(reto);
			//String location = "4.6071233,-74.0815995";
			byte[] retoInBytes = DatatypeConverter.parseBase64Binary(reto);

			//decrypt reto
			Cipher cipher1 = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			//GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initVector.getBytes("UTF-8")); //128 bit auth tag length
			//IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			//cipher1.init(Cipher.DECRYPT_MODE, this.symmetricKey, iv);
			cipher1.init(Cipher.DECRYPT_MODE, this.symmetricKey);
			//cipher1.init(this.symmetricKey);
			byte[] decryptedRetoInBytes = cipher1.doFinal(retoInBytes);
			String decryptedRetoString = DatatypeConverter
					.printBase64Binary(decryptedRetoInBytes );

			System.out.println(decryptedRetoString);

			byte[] retoInAssymetricBytes = AsymmetricCryprography
					.encrypt(keyPair.getPublic(), decryptedRetoString);

			String respuesta = DatatypeConverter.printBase64Binary(retoInAssymetricBytes);

			out.println(respuesta);

			/*
			// encrypt reto with symetric key. We send it.
			Cipher cipher = Cipher.getInstance(Padding);
			cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey);
			byte[] cipheredlocationTextArray = cipher.doFinal(locationInBytes);
			String cipheredTextHexadecimal = DatatypeConverter
					.printHexBinary(cipheredlocationTextArray);
			String strToSend = "ACT1" + SEPARADOR + cipheredTextHexadecimal;
			out.println(strToSend);

			// We calculate the digest, encrypt it with server public key, We send it.
			byte[] digest = HMACDigestCreator.getkeyedDigest(locationInBytes, ALGD,
					this.symmetricKey);

			Cipher rsa;
			try {
				rsa = Cipher.getInstance(ALGA);
				rsa.init(Cipher.ENCRYPT_MODE, serverKey);
				byte[] encryptedDigest = rsa.doFinal(digest);
				String encryptedDigestString = DatatypeConverter
						.printHexBinary(encryptedDigest);
				strToSend = "ACT2" + SEPARADOR + encryptedDigestString;

				out.println(strToSend);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

			receiveResponse();
		*/
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void receiveResponse() {

		String line;

		try {
			line = in.readLine();
			String[] lineParts = line.split(SEPARADOR);
			if (line != null) {
				String finalResult = lineParts[1];
				System.out.println("Final answer of the server was: " + finalResult);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {
		Client client = new Client();
		client.connect();
	}
}
