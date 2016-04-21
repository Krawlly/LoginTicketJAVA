package com.krawlly.util.ticket;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.CertificateException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for TicketFactory.
 */
public class TicketFactoryTest extends TestCase {
	/**
	 * Create the test case
	 *
	 * @param testName
	 *            name of the test case
	 */
	public TicketFactoryTest(String testName) {
		super(testName);
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(TicketFactory.class);
	}

	public void testCreationFromFile() throws CertificateException, MalformedURLException, IOException {
		TicketFactory tf = new TicketFactory(new CertificateFile(new File("test.crt")));
		assertNotNull(tf);
	}
}
