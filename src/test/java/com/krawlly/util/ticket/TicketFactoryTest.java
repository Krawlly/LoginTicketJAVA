package com.krawlly.util.ticket;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.CertificateException;

import com.krawlly.util.ticket.TicketFactory.TicketWithHmac;

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
		return new TestSuite(TicketFactoryTest.class);
	}

	public void testCreationFromFile() throws CertificateException, MalformedURLException, IOException {
		TicketFactory tf = new TicketFactory(new CertificateFile(new File("src/test/resources/test.crt")));
		assertNotNull(tf);
	}

	public void testCreationFromUrl() throws CertificateException, MalformedURLException, IOException {
		TicketFactory tf = new TicketFactory(new CertificateURL(getClass().getClassLoader().getResource("test.crt")));
		assertNotNull(tf);
	}

	public void testCreationFromString() throws CertificateException, MalformedURLException, IOException {
		byte[] data = ("-----BEGIN CERTIFICATE-----\n"
				+ "MIICnDCCAYSgAwIBAgIEVxkWKTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0\n"
				+ "ZXN0MCAXDTE2MDQyMTE4MDQzOFoYDzMwMTUwNDIxMTgwNDM4WjAPMQ0wCwYDVQQD\n"
				+ "DAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArtnYfCyPjHDS\n"
				+ "SriWxyx/3kq1YFYECNiQRajG67nPkJ0U7cOuMxooBss/7mg7DHZ8BU08v8ljtXGT\n"
				+ "gyvrClkKEhoY/IepBVWiULiX7yK6hsozH8Fq2GuT6TPxH6J4jvJMfffOBa811Mqi\n"
				+ "wOTj83kWuD185aS5qA2exL7UWNGvg7G3+7QzNm/gRWosSZ5CBU2M0eYybK+BhNqt\n"
				+ "hxAyxfK0gYkIqYO8FZZqYGFU1T2xzWceqIA52mqsltjbim9iVtuDgdoCEqyQc/T3\n"
				+ "M0xNCXDiD6HLfO1dVOgRZ3Huv/4mEzNtcNXlRz56dkrzSXmmHmcFvqHeZF4l5GXI\n"
				+ "MQ9xdFQYwwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBigLbQkwxg/4Q9yLZ3OE6h\n"
				+ "01hhj6zkFQawxm4ge2qLYrAQpNtntFw8nEgVqqYVO8HbTnnVdG+Xalje+WvcbS8Y\n"
				+ "DwnXItk1Dvjp+v/dr0ZShH3EJr3I0MHmB5P+X28UqbnLq/4knxICFjLlCo9hmhRz\n"
				+ "mj6uhxJ/SM8zCweLKEYXMwNreKUD51T4KQ3h9X+1A9eNJjfVPdCqIHsgIgUVUREu\n"
				+ "hd6eahYVu87Gz+Cwj6Af8nOxJ2OuYhznCXcRliI9IaCsg+fMYssRo3Tfyf4nEcUx\n"
				+ "TTEo4ZAwhw+FDcMhQWssOa9zLZI+OP01xW76AIcpMBhrSiC5zI8Bnwwfhbsq7Sy9\n" + "-----END CERTIFICATE-----")
				.getBytes();
		TicketFactory tf = new TicketFactory(new CertificateData(data));
		assertNotNull(tf);
	}

	public void testTicketFormatting() throws CertificateException, MalformedURLException, IOException {
		TicketFactory tf = new TicketFactory(new CertificateURL(getClass().getClassLoader().getResource("test.crt")));
		Ticket ticket = new LoginTicket("Test", 100);
		String t = tf.createTicket(ticket);
		assertNotNull(t);
		assertFalse(t.isEmpty());
	}

	public void testTicketFormattingWithHmac() throws CertificateException, MalformedURLException, IOException {
		TicketFactory tf = new TicketFactory(new CertificateURL(getClass().getClassLoader().getResource("test.crt")));
		Ticket ticket = new LoginTicket("Test", 100);
		TicketWithHmac th = tf.createTicketWithHmac(ticket);
		assertNotNull(th.ticket);
		assertNotNull(th.hmac);
		assertFalse(th.ticket.isEmpty());
		assertFalse(th.hmac.length <= 0);
	}
}
