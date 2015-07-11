package me.xephore.virustotal2bind.packets;

import java.util.HashSet;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class PacketResolutionDecoder implements Decoder {
	
	private final JSONObject obj;
	private final Set<String> data = new HashSet<String>();
	
	public PacketResolutionDecoder(JSONObject obj) {
		this.obj = obj;
	}
	
	@Override
	public void decode() {
		data.clear();
		JSONArray array = (JSONArray) obj.get("resolutions");
		
		String name = array.toString().replace("{", "").replace("}", "").replace("[", "").replace("]", "");
		
		String[] args = name.split(",");
		for(String code : args) {
			String ip = code.split(":")[1];
			String fixedip = ip.substring(1, ip.length()-1).replace("www.", "");
			if(!fixedip.contains("-")) {
				data.add(fixedip);	
			}
		}
	}
	
	@Override
	public Object getResult() {
		String bind = "";
		for(String a : data) {
			if(DomainPacket.isUrl(a)) {
				
				String as[] = a.split(".");
				
				String newdomain = "";
				
				if(as.length > 1) {
					newdomain = as[as.length-1] + as[as.length];	
				} else {
					newdomain = a;
				}
				
				bind += "zone \""+newdomain+"\" {\n" +
				"    type master;\n" +
				"    file \"/etc/bind/blocked.db\";\n" +
				"};\n";
				bind += "zone \"*."+newdomain+"\" {\n" +
				"    type master;\n" +
				"    file \"/etc/bind/blocked.db\";\n" +
				"};\n";
			} else {
				bind += "zone \""+a+"\" {\n" +
				"    type master;\n" +
				"    file \"/etc/bind/blocked.db\";\n" +
				"};\n";
			}
		}
		return bind;
	}

}
