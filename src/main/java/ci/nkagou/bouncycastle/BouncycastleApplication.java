package ci.nkagou.bouncycastle;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.util.Store;

@SpringBootApplication
public class BouncycastleApplication {

    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException, KeyStoreException, UnrecoverableKeyException, CMSException, OperatorCreationException {
        SpringApplication.run(BouncycastleApplication.class, args);


       Security.setProperty("crypto.policy", "unlimited");

        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);


        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory= CertificateFactory.getInstance("X.509", "BC");

       // X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("C:\\keys\\bouncy\\Baeldung.cer"));
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("C:\\keys\\bouncy\\nkagouci.cer"));

        char[] keystorePassword = "Mjk@23ffKhg#@@".toCharArray();
        //char[] keyPassword = "password".toCharArray();
        char[] keyPassword = "Mjk@23ffKhg#@@".toCharArray();


        KeyStore keystore = KeyStore.getInstance("PKCS12");
       // keystore.load(new FileInputStream("C:\\keys\\bouncy\\Baeldung.p12"), keystorePassword);
        keystore.load(new FileInputStream("C:\\keys\\bouncy\\nkagouci.p12"), keystorePassword);
        PrivateKey key = (PrivateKey) keystore.getKey("nkagouci", keyPassword);


        String secretMessage = "My password is 123456Seven&";
        System.out.println("Original Message : " + secretMessage);
        byte[] stringToEncrypt = secretMessage.getBytes();
        byte[] encryptedData = encryptData(stringToEncrypt, certificate);

        //String originalInput = "test input";
        //String encodedString = Base64.getEncoder().encodeToString(encryptedData);
        String encodedString = Base64.getUrlEncoder().encodeToString(encryptedData);

        String url = "https://nkagou.ci/api/v1/"+encodedString;
        System.out.println("Url : " + url);
        System.out.println("Encrypted Message : " + new String(encryptedData));
        System.out.println("Encrypted Message Base 64 : " + encodedString);

        //byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(encodedString);


        //byte[] rawData = decryptData(encryptedData, key);
        byte[] rawData = decryptData(decodedBytes, key);
        String decryptedMessage = new String(rawData);
        System.out.println("Decrypted Message : " + decryptedMessage);

        String data = "test";
        byte[] byteData = data.getBytes();


        byte[] signData = signData(byteData, certificate, key);



        Boolean check = verifSignData(signData);

        System.out.println(check);



        String q ="";
    }

    public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg,encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static byte[] decryptData(final byte[] encryptedData, final PrivateKey decryptionKey) throws CMSException {
        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
            Collection<RecipientInformation> recip = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recip.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
            decryptedData = recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    public static byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey) throws CertificateEncodingException, OperatorCreationException, CMSException, IOException, OperatorCreationException {
        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);
        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    public static boolean verifSignData(final byte[] signedData) throws CMSException, IOException, OperatorCreationException, CertificateException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(signedData);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
        aIn.close();
        bIn.close();
        Store certs = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        SignerInformation signer = c.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();
        boolean verifResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        if (!verifResult) {
            return false;
        }
        return true;
    }

}
