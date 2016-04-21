package com.krawlly.util.ticket;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import com.krawlly.util.ticket.TicketFactory.CertificateProvider;

public class CertificateData implements CertificateProvider {

	private final byte[] cert;

	public CertificateData(byte[] certificate) {
		this.cert = certificate;
	}

	public Certificate getCertificate(CertificateFactory cf) throws IOException, CertificateException {
		InputStream is = null;
		try {
			is = new ByteArrayInputStream(cert);
			return cf.generateCertificate(is);
		} finally {
			if (is != null)
				is.close();
		}
	}
}