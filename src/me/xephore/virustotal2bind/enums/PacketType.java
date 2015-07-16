package me.xephore.virustotal2bind.enums;

import java.net.MalformedURLException;
import java.net.URL;

public enum PacketType {
	
	DOMAIN("https://www.virustotal.com/vtapi/v2/domain/report"),
	IP("https://www.virustotal.com/vtapi/v2/ip-address/report");
	
	private final String provider;
	
	private PacketType(String provider) {
		this.provider = provider;
	}
	
	public URL getProvider() {
		try {
			return new URL(provider);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		return null;
	}

}
