package me.xephore.virustotal2bind.packets;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class PacketDetectionDecoder implements Decoder {
	
	private final JSONObject obj;
	private int detections = 0;
	
	public PacketDetectionDecoder(JSONObject obj) {
		this.obj = obj;
	}
	
	@Override
	public void decode() {
		JSONArray array = (JSONArray) obj.get("detected_urls");
		
		String name = array.toString().replace("{", "").replace("}", "").replace("[", "").replace("]", "");
		
		String[] args = name.split(",");
		
		for(String a : args) {
			if(a.contains("total")) {
				this.detections = (this.detections+Integer.parseInt(a.replace("\"total\":", "")));
			}
		}
	}
	
	@Override
	public Object getResult() {
		return "detections: " + detections;
	}

}
