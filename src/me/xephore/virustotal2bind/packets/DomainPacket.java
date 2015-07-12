package me.xephore.virustotal2bind.packets;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.xephore.virustotal2bind.Configuration;

public class DomainPacket implements Packet {

	private String domain;

	@Override
	public String getName() {
		return "Domain-packet";
	}

	@Override
	public PacketType getType() {
		return PacketType.DOMAIN;
	}

	@Override
	public String[] getParams() {
		return new String[]{domain, Configuration.getConfiguration().getApiKey()};
	}

	public void setDomainNameParam(String name) {
		if(isUrl(name)) {
			this.domain = name;
		} else {
			throw new IllegalArgumentException("the domain name has to be a valid url!");	
		}
	}

	@Override
	public boolean isPacketComplete() {
		if(domain != null && Configuration.getConfiguration().getApiKey() != null) {
			return true;
		}
		return false;
	}

	public static boolean isUrl(String data) {
		Pattern p = Pattern.compile("^[A-Za-z0-9\\.]*\\.(co|biz|com|jobs|mobi|travel|net|org|pro|tel|info|xxx|name|ac|ag|am|asia|at|be|bz|cc|cn|cx|de|eu|fm|gs|hn|ht|im|in|io|it|jp|ki|la|lc|me|mn|mx|nf|nl|sb|sc|se|sh|tl|tv|tw|uk|us|vc|ws|ru)");
		Matcher match = p.matcher(data);
		return match.matches();
	}

}
