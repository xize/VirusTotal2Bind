package me.xephore.virustotal2bind.packets;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.xephore.virustotal2bind.Configuration;
import me.xephore.virustotal2bind.enums.PacketType;

public class IPAddressPacket implements Packet {

	private String ip;

	@Override
	public String getName() {
		return "Ip-packet";
	}

	@Override
	public PacketType getType() {
		return PacketType.IP;
	}

	@Override
	public String[] getParams() {
		return new String[] {ip, Configuration.getConfiguration().getApiKey()};
	}

	@Override
	public boolean isPacketComplete() {
		if(ip != null) {
			return true;
		}
		return false;
	}

	@SuppressWarnings("unused")
	public void setIpAdressParam(String ip) {
		try {
			InetAddress address = InetAddress.getByName(ip);
			this.ip = ip;
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
	}

	public static boolean isIp(String ip) {
		String PATTERN = "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
	     Pattern pattern = Pattern.compile(PATTERN);
	     Matcher matcher = pattern.matcher(ip);
	     return matcher.matches();
	}

}
