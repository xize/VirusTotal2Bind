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
		data.add(sourceIp);
		JSONArray array = (JSONArray) obj.get("resolutions");

		String name = array.toString().replace("{", "").replace("}", "").replace("[", "").replace("]", "");

		String[] args = name.split(",");

		if(args.length != 0) {
			for(String code : args) {
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

	@Override
	public Object getResult() {
		String bind = "";
		for(String a : data) {
			if(DomainPacket.isUrl(a)) {
				bind += "zone \""+a+"\" {\n" +
						"    type master;\n" +
						"    file \"/etc/bind/blocked.db\";\n" +
						"};\n";
				bind += "zone \"*."+a+"\" {\n" +
						"    type master;\n" +
						"    file \"/etc/bind/blocked.db\";\n" +
						"};\n";
			} else if(IPAddressPacket.isIp(a)) {
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
