package client;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

//import javax.xml.bind.DatatypeConverter;

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
			System.out.print(answer);
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
			String certificadoEnString = DatatypeConverter.printBase64Binary(certificadoEnBytes);

			try {
				s.getOutputStream().write(certAsBytes);
				s.getOutputStream().flush();
			} catch (IOException exception) {
				System.out.println("There was an error sending bytes to server");
			}

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
			String validation = in.readLine();
			out.println(OK);
			if (validation.equals(CERTSRV)) {
				// check the quality of the certificate
				try {
					CertificateFactory certFactory = CertificateFactory
							.getInstance("X.509");
					byte[] serverCertificateInBytes = new byte[5000]; // buffer to save
																														// certificate bytes
					inputStream.read(serverCertificateInBytes);
					InputStream in = new ByteArrayInputStream(serverCertificateInBytes);
					serverCertificate = (X509Certificate) certFactory
							.generateCertificate(in);
					serverKey = serverCertificate.getPublicKey();

				} catch (Exception e) {
					out.println(ESTADO + SEPARADOR + ERROR);
					System.out.println(
							"Error in the received certificate. It cannot be decoded");
					e.printStackTrace();

				}
				out.println(ESTADO + SEPARADOR + OK);

				receiveSimmetricKey();

			} else {
				System.out.println("CERTSRV expected. Connection terminated");
				s.close();
			}

		} catch (IOException e) {
			System.out.println(
					"Error reading line that announces the server will send its certificate");
		}

	}

	private void receiveSimmetricKey() {
		String line;
		try {
			line = in.readLine();
			String[] lineParts = line.split(":");
			//byte[] parsedLine = DatatypeConverter
			//		.parseHexBinary(lineParts[lineParts.length - 1]);
			//byte[] symmetricKeyArray = AsymmetricCryprography
			//		.decrypt(keyPair.getPrivate(), parsedLine);

			//SecretKeySpec symmetricKey = new SecretKeySpec(symmetricKeyArray, ALGS);
			this.symmetricKey = symmetricKey;
			System.out.println("Symmetric key stablished in client");
			sendLocationAndDigest();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void sendLocationAndDigest() {

		try {

			String location = "4.6071233,-74.0815995";
			byte[] locationInBytes = location.getBytes(Encoding);

			// encrypt location with symetric key. We send it.
			Cipher cipher = Cipher.getInstance(Padding);
			cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey);
			byte[] cipheredlocationTextArray = cipher.doFinal(locationInBytes);
			//String cipheredTextHexadecimal = DatatypeConverter
			//		.printHexBinary(cipheredlocationTextArray);
			String strToSend = "ACT1" + SEPARADOR; //+ cipheredTextHexadecimal;
			out.println(strToSend);

			// We calculate the digest, encrypt it with server public key, We send it.
			byte[] digest = HMACDigestCreator.getkeyedDigest(locationInBytes, ALGD,
					this.symmetricKey);

			Cipher rsa;
			try {
				rsa = Cipher.getInstance(ALGA);
				rsa.init(Cipher.ENCRYPT_MODE, serverKey);
				byte[] encryptedDigest = rsa.doFinal(digest);
				//String encryptedDigestString = DatatypeConverter
				//		.printHexBinary(encryptedDigest);
				strToSend = "ACT2" + SEPARADOR; //+ encryptedDigestString;

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