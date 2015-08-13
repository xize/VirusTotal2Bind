package me.xephore.virustotal2bind.packets;

import java.util.HashSet;
import java.util.Set;

import me.xephore.virustotal2bind.GuiApi;
import me.xephore.virustotal2bind.Main;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class PacketResolutionDecoder implements Decoder {

	private final JSONObject obj;
	private final Set<String> data = new HashSet<String>();
	private final String sourceIp;
	private GuiApi gui;
	
	public PacketResolutionDecoder(JSONObject obj, String ip, GuiApi gui) {
		this.obj = obj;
		this.sourceIp = ip;
		this.gui = gui;
	}
	
	public PacketResolutionDecoder(JSONObject obj, String ip) {
		this.obj = obj;
		this.sourceIp = ip;
	}

	@Override
	public void decode() {
		data.clear();
		JSONArray array = (JSONArray) obj.get("resolutions");

		if(array == null) {
			Main.getLogger().severe("could not define resolutions?, disconnected");
			Main.getLogger().severe("obj: " + obj.toJSONString());
			return;
		}
		
		String name = array.toString().replace("{", "").replace("}", "").replace("[", "").replace("]", "").replace("http://", "").replace("%", "");
		
		//System.out.println(name);
		
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
						(gui == null ? toSpacedString("type master;\nfile \"/etc/bind/blocked.db\"") : toSpacedString(gui.getZoneOutputData().getText())) +
						"};\n";
				bind += "zone \"*."+a+"\" {\n" +
						(gui == null ? toSpacedString("type master;\nfile \"/etc/bind/blocked.db\"") : toSpacedString(gui.getZoneOutputData().getText())) +
						"};\n";
			} else if(IPAddressPacket.isIp(a)) {
				if(bind == null) {bind = "";}
				bind += "zone \""+a+"\" {\n" +
						(gui == null ? toSpacedString("type master;\nfile \"/etc/bind/blocked.db\"") : toSpacedString(gui.getZoneOutputData().getText())) +
						"};\n";
			} else {
				Main.getLogger().info("WARNING: unknown url or regex could not determine what this is!: " + a);
			}
		}
		return bind;
	}
	
	private String toSpacedString(String data) {
		String[] datas = data.split("\n");
		String newdata = "";
		for(String a : datas) {
			newdata  += "    " + a + "\n";
		}
		return newdata;
	}

}
