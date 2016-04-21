package com.krawlly.util.ticket;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class TicketFactory {

	public static final String DEFAULT_CERTIFICATE_TYPE = "X.509";
	public static final String DEFAULT_CERTIFICATE_KEY_ALGORYTHM = "RSA";
	public static final String DEFAULT_HMAC_ALGORYTHM = "HmacSHA1";

	public static final FactorySettings DEFAULT_SETTINGS = new FactorySettings("AES", "AES/GCM/NoPadding",
			DEFAULT_CERTIFICATE_TYPE, DEFAULT_CERTIFICATE_KEY_ALGORYTHM);

	public static class FactorySettings {

		private final String keyAlgorithm;
		private final String cipherTransformation;
		private final String certificateType;
		private final String certificateKeyAlgorithm;

		public FactorySettings(String keyAlgorithm, String cipherTransformation) {
			this(keyAlgorithm, cipherTransformation, DEFAULT_CERTIFICATE_TYPE, DEFAULT_CERTIFICATE_KEY_ALGORYTHM);
		}

		public FactorySettings(String keyAlgorithm, String cipherTransformation, String certificateType,
				String certificateKeyAlgorithm) {
			this.keyAlgorithm = keyAlgorithm;
			this.cipherTransformation = cipherTransformation;
			this.certificateType = certificateType;
			this.certificateKeyAlgorithm = certificateKeyAlgorithm;
		}
	}

	private static interface TicketGenerator {

		String getTicket();

		byte[] getHmac(String algorithm);
	}

	public static final class TicketWithHmac {
		public final String ticket;
		public final byte[] hmac;

		private TicketWithHmac(String ticket, byte[] hmac) {
			this.ticket = ticket;
			this.hmac = hmac;
		}
	}

	public static interface CertificateProvider {
		Certificate getCertificate(CertificateFactory cf) throws IOException, CertificateException;
	}

	public TicketFactory(CertificateProvider cp) throws CertificateException, IOException {
		this(cp, DEFAULT_SETTINGS);
	}

	private final Cipher cik;
	private final Cipher cip;
	private final FactorySettings settings;

	public TicketFactory(CertificateProvider cp, FactorySettings settings) throws CertificateException, IOException {
		this.settings = settings;
		final Certificate certificate = cp.getCertificate(CertificateFactory.getInstance(settings.certificateType));
		try {
			this.cik = Cipher.getInstance(settings.certificateKeyAlgorithm);
			cik.init(Cipher.WRAP_MODE, certificate);
			this.cip = Cipher.getInstance(settings.certificateKeyAlgorithm);
			cip.init(Cipher.ENCRYPT_MODE, certificate);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Certificate is invalid, damaged or has wrong format.", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Certificate key algorithm not found in system.", e);
		} catch (NoSuchPaddingException e) {
			throw new IllegalArgumentException("Certificate padding algorithm not found in system.", e);
		}
	}

	public String createTicket(Ticket ticket) throws IOException {
		return createTicket(ticket.getTicketContents());
	}

	public String createTicket(String ticket) throws IOException {
		return createTicket(ticket.getBytes());
	}

	public String createTicket(byte[] ticket) throws IOException {
		return createTicketGenerator(ticket).getTicket();
	}

	public TicketWithHmac createTicketWithHmac(Ticket ticket) throws IOException {
		return createTicketWithHmac(ticket.getTicketContents());
	}

	public TicketWithHmac createTicketWithHmac(String ticket) throws IOException {
		return createTicketWithHmac(ticket.getBytes());
	}

	public TicketWithHmac createTicketWithHmac(byte[] ticket) throws IOException {
		TicketGenerator tg = createTicketGenerator(ticket);
		return new TicketWithHmac(tg.getTicket(), tg.getHmac(DEFAULT_HMAC_ALGORYTHM));
	}

	private TicketGenerator createTicketGenerator(final byte[] message) throws IOException {
		try {
			final KeyGenerator kg = KeyGenerator.getInstance(settings.keyAlgorithm);
			kg.init(SecureRandom.getInstanceStrong());
			final Key key = kg.generateKey();

			final Cipher cid = Cipher.getInstance(settings.cipherTransformation);
			cid.init(Cipher.ENCRYPT_MODE, key);

			byte[] settings = null;
			DerOutputStream settingsStream = null;
			try {
				settingsStream = new DerOutputStream();
				DerOutputStream bytesStream = null;
				try {
					bytesStream = new DerOutputStream();

					bytesStream.putIA5String(key.getAlgorithm());
					bytesStream.putIA5String(cid.getAlgorithm());
					bytesStream.putDerValue(new DerValue(cid.getParameters().getEncoded("ASN.1")));

					settingsStream.write(DerValue.tag_Sequence, bytesStream);
					settings = settingsStream.toByteArray();

				} finally {
					if (bytesStream != null)
						bytesStream.close();
				}
			} finally {
				if (settingsStream != null)
					settingsStream.close();
			}

			if (settings == null)
				throw new NullPointerException("Cipher key and transformation settings is null.");

			ByteArrayOutputStream baos = null;
			try {
				baos = new ByteArrayOutputStream();

				baos.write(cip.doFinal(settings));
				baos.write(cik.wrap(key));
				baos.write(cid.doFinal(message));

				final byte[] ticketData = baos.toByteArray();
				return new TicketGenerator() {
					public String getTicket() {
						return DatatypeConverter.printBase64Binary(ticketData);
					}

					public byte[] getHmac(String algorithm) {
						try {
							Mac mac = Mac.getInstance(algorithm);
							mac.init(key);
							return mac.doFinal(message);
						} catch (NoSuchAlgorithmException e) {
							throw new IllegalArgumentException("HMAC algorithm not found in system.", e);
						} catch (InvalidKeyException e) {
							throw new IllegalArgumentException("Ticket key can't be used for HMAC generation.", e);
						}
					}
				};

			} finally {
				if (baos != null)
					baos.close();
			}
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Ticket key algorithm not found in system.", e);
		} catch (NoSuchPaddingException e) {
			throw new IllegalArgumentException("Ticket padding algorithm not found in system.", e);
		} catch (InvalidKeyException e) {
			throw new IOException("Ticket key is malformed or damaged.", e);
		} catch (IllegalBlockSizeException e) {
			throw new IOException("Ticket encryption can't be done.", e);
		} catch (BadPaddingException e) {
			throw new IOException("Ticket padding is malformed or damaged.", e);
		}
	}
}
