package com.krawlly.util.ticket;

import java.io.File;
import java.net.MalformedURLException;

public class CertificateFile extends CertificateURL {
	public CertificateFile(File certificateFile) throws MalformedURLException {
		super(certificateFile.toURI().toURL());
	}
}