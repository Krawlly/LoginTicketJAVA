package com.krawlly.util.ticket;

import java.util.Calendar;
import java.util.Date;
import java.lang.StringBuilder;

public final class LoginTicket implements Ticket {

	private final String ticket;

	public LoginTicket(String userName, Date validThrough) {
		this.ticket = fomatJson(userName, validThrough);
	}

	public LoginTicket(String userName, int minutes) {
		this(userName, makeValidThrough(minutes));
	}

	public String getTicketContents() {
		return ticket;
	}

	private static final Date makeValidThrough(int minutes) {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, minutes);
		return cal.getTime();
	}

	private static final String fomatJson(String userName, Date validThrough) {
		StringBuilder sb = new StringBuilder();
		sb.append("{\"userName\":\"");
		sb.append(userName);
		sb.append("\",\"validThrough\":");
		sb.append(validThrough.getTime());
		sb.append("}");
		return sb.toString();
	}
}