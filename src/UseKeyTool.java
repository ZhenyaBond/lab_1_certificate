import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import sun.security.pkcs10.PKCS10;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;


public class UseKeyTool {

    private static final int keysize = 2048;
    private static final String commonName = "BSTU";
    private static final String organizationalUnit = "BSTU";
    private static final String organization = "BSTU";
    private static final String location = "Minsk";
    private static final String state = "Minsk";
    private static final String country = "BY";
    private static final long validity = 1096;
    private static final String alias = "BY";
    private static final char[] keyPass = "bstu".toCharArray();

    private static KeyStore  keyStore= null;
    private static PublicKey publicKey = null;
    private static PrivateKey privateKey = null;
    private static CertAndKeyGen keyPair = null;



    public void getKeystore() throws Exception{
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        keyPair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);

        X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, location, state, country);

        keyPair.generate(keysize);
        privateKey = keyPair.getPrivateKey();
        publicKey = keyPair.getPublicKey();

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = keyPair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);

        keyStore.setKeyEntry(alias, privateKey, keyPass, chain);
        keyStore.store(new FileOutputStream("k.keystore"), keyPass);
    }

    public void getCSR() throws Exception {

        String sigAlg = "SHA1WithRSA";
        PKCS10 pkcs10 = new PKCS10(publicKey);
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);

        X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, location, state, country);
        pkcs10.encodeAndSign(x500Name,signature);

        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        byte[] c = bs.toByteArray();
        try {
            if (ps != null)
                ps.close();
            if (bs != null)
                bs.close();
        } catch (Throwable th) {
        }
        FileWriter fileWriter = new FileWriter("csr.csr");
        BufferedWriter bw = new BufferedWriter(fileWriter);
        bw.write(new String(c));
        bw.close();

        System.out.println(new String(c));
    }

    public void getCertificate() throws KeyStoreException, IOException {
        System.out.println(keyStore.getCertificate(alias));

        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        FileWriter fileWriter = new FileWriter("cert.crt");
        BufferedWriter bw = new BufferedWriter(fileWriter);
        bw.write(cert.toString());
        bw.close();

    }




    public static void main(String[] args) throws Exception {
        UseKeyTool certificate = new UseKeyTool();
        certificate.getKeystore();
        certificate.getCSR();
        certificate.getCertificate();
    }

}
