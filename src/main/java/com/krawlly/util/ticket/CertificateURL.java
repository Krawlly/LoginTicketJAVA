package com.krawlly.util.ticket;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import com.krawlly.util.ticket.TicketFactory.CertificateProvider;

public class CertificateURL implements CertificateProvider {

	private final URL certUrl;

	public CertificateURL(URL certificateUrl) {
		this.certUrl = certificateUrl;
	}

	public Certificate getCertificate(CertificateFactory cf) throws IOException, CertificateException {
		InputStream is = null;
		try {
			is = certUrl.openStream();
			return cf.generateCertificate(is);
		} finally {
			if (is != null)
				is.close();
		}
	}
}