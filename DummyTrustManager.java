package imapClient;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * This class create TrustManager with our own KeyStore and standard KeyStore.
 *  - Form.certFile = "certificates"; (File to stored our own certificates)
 *  - Form.certFilePass = "simplePassword"; (Password to unlock the keystore)
 *  - Form.defaultCertFilePass = "changeit"; (Standard password)
 */

public class DummyTrustManager implements X509TrustManager {
	
	X509TrustManager pkixTrustManager;
	
	DummyTrustManager() throws Exception {
		
		//Loads the KeyStore from its own "certificates" file, if one exists. 
		KeyStore ts = KeyStore.getInstance("JKS");
		File certificates = new File(Form.certFile);
		if (certificates.exists()) ts.load(new FileInputStream(certificates), Form.certFilePass.toCharArray());
		else ts.load(null, null);
		
	    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	    
	    //Loads the KeyStore from standard trust store java-home/lib/security/jssecacerts, 
	    //if one exists. Otherwise from java-home/lib/security/cacerts.
		File defaultCAcerts = new File(getdefaultPath());		
		if (defaultCAcerts.exists()) {
			KeyStore defaultTs = KeyStore.getInstance("JKS");
			defaultTs.load(new FileInputStream(defaultCAcerts), Form.defaultCertFilePass.toCharArray());
			
			//We combine our own KeyStore and standard KeyStore.
			Enumeration<String> aliases = ts.aliases();	    	
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				defaultTs.setCertificateEntry(alias, ts.getCertificate(alias));
			}
			tmf.init(defaultTs);
		} else tmf.init(ts);
		
		TrustManager tms [] = tmf.getTrustManagers();
		for (int i = 0; i < tms.length; i++) {
			if (tms[i] instanceof X509TrustManager) {
				pkixTrustManager = (X509TrustManager) tms[i];
				return;
			}
		}
		throw new Exception("ERROR: Couldn't initialize cacerts"); 
	}
	
	public static String getdefaultPath() {
		String defaultPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator;	
		if (new File(defaultPath + "jssecacerts").exists()) return defaultPath + "jssecacerts";
		return defaultPath + "cacerts";
	}
	
    public void checkClientTrusted(X509Certificate[] cert, String authType) throws CertificateException {
    	pkixTrustManager.checkClientTrusted(cert, authType);

    }

    public void checkServerTrusted(X509Certificate[] cert, String authType) throws CertificateException {
    	pkixTrustManager.checkServerTrusted(cert, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
    	return pkixTrustManager.getAcceptedIssuers();
    }
}