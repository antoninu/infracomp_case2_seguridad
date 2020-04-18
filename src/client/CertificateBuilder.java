package client;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateBuilder {
	
	public static X509Certificate buildX509Certificate(KeyPair keyPair) throws OperatorCreationException, CertificateException{
	// Generate self-signed certificate
			Calendar endCalendar = Calendar.getInstance();
			endCalendar.add(Calendar.YEAR,10);
			X509v3CertificateBuilder  x509CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"),BigInteger.valueOf(1),Calendar.getInstance().getTime(),endCalendar.getTime(),new X500Name("CN=localhoost"),SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())) ;
            ContentSigner contetnSigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());
            X509CertificateHolder X509CertificateHolder = x509CertificateBuilder.build(contetnSigner);
            
            return new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).getCertificate(X509CertificateHolder);
}
}
