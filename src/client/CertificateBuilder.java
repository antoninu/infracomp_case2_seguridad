package client;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateBuilder {
	
	public static X509Certificate buildX509Certificate(KeyPair keyPair){
	// Generate self-signed certificate
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.OU, "OU");
			nameBuilder.addRDN(BCStyle.O, "O");
			nameBuilder.addRDN(BCStyle.CN, "CN");

			String stringDate1 = "2016-10-01";
			String stringDate2 = "2020-12-20";
			DateFormat format = new SimpleDateFormat("yyyy-MM-dd");
			Date notBefore = null;
			Date notAfter = null;
			try {
				notBefore = format.parse(stringDate1);
				notAfter = format.parse(stringDate2);
			} catch (ParseException e) {
				e.printStackTrace();
			}
			BigInteger serialNumber = new BigInteger(128, new Random());

			X509v3CertificateBuilder certificateBuilder =
					new JcaX509v3CertificateBuilder(nameBuilder.build(), serialNumber, notBefore, notAfter, nameBuilder.build(),
							keyPair.getPublic());
			X509Certificate certificate = null;
			try {
				ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

				certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
			} catch (OperatorCreationException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			}
			return certificate;
		
	}

}
