package me.xephore.virustotal2bind.packets;

import java.util.HashSet;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class PacketResolutionDecoder implements Decoder {

	private final JSONObject obj;
	private final Set<String> data = new HashSet<String>();
	private final String sourceIp;

	public PacketResolutionDecoder(JSONObject obj, String ip) {
		this.obj = obj;
		this.sourceIp = ip;
	}

	@Override
	public void decode() {
		data.clear();
		JSONArray array = (JSONArray) obj.get("resolutions");

		String name = array.toString().replace("{", "").replace("}", "").replace("[", "").replace("]", "").replace("http://", "").replace("%", "");
		
		System.out.println(name);
		
		String[] args = name.split(",");

		if(args.length >= 1) {
			for(String code : args) {
				if(code.contains(":")) {
					String ip = code.split(":")[1];
					String fixedip = ip.substring(1, ip.length()-1).replace("www.", "");
					if(!fixedip.contains("-")) {
						if(DomainPacket.isUrl(fixedip)) {
							String as[] = fixedip.split("\\.");

							String newdomain = "";

							if(as.length > 2) {
								newdomain = as[as.length-2] + "." + as[as.length-1];
							}
							fixedip = newdomain;
						}

						data.add(fixedip);
					}
				}
			}
		}
		if(!data.isEmpty()) {
			data.add(sourceIp);
		}
	}

	@Override
	public Object getResult() {
		String bind = null;
		for(String a : data) {
			if(DomainPacket.isUrl(a)) {
				if(bind == null) {bind = "";}
				bind += "zone \""+a+"\" {\n" +
						"    type master;\n" +
						"    file \"/etc/bind/blocked.db\";\n" +
						"};\n";
				bind += "zone \"*."+a+"\" {\n" +
						"    type master;\n" +
						"    file \"/etc/bind/blocked.db\";\n" +
						"};\n";
			} else if(IPAddressPacket.isIp(a)) {
				if(bind == null) {bind = "";}
				bind += "zone \""+a+"\" {\n" +
						"    type master;\n" +
						"    file \"/etc/bind/blocked.db\";\n" +
						"};\n";
			} else {
				System.out.println("WARNING: unknown url or regex could not determine what this is!: " + a);
			}
		}
		return bind;
	}

}
