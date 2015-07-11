package me.xephore.virustotal2bind.packets;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class PacketFactory {
	
	private final static PacketFactory factory = new PacketFactory();
	
	private PacketFactory() {}

	public String sentPacket(Packet packet) {
		try {
			if(packet.getType() == PacketType.DOMAIN) {
				URL url = new URL(packet.getType().getProvider().toString() + "?domain="+packet.getParams()[0] + "&apikey="+packet.getParams()[1]);
				HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
				con.setRequestMethod("GET");
				con.setDoOutput(true);
				InputStreamReader ireader = new InputStreamReader(con.getInputStream());
				BufferedReader breader = new BufferedReader(ireader);
				
				JSONParser parse = new JSONParser();
				JSONObject array = (JSONObject) parse.parse(breader);
				
				Decoder decoder = new PacketResolutionDecoder(array);
				decoder.decode();
				String bind = (String)decoder.getResult();
				breader.close();
				ireader.close();
				con.disconnect();
				
				return bind;
			} else if(packet.getType() == PacketType.IP) {
				URL url = new URL(packet.getType().getProvider().toString() + "?ip="+packet.getParams()[0] + "&apikey="+packet.getParams()[1]);
				HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
				con.setRequestMethod("GET");
				
				InputStreamReader ireader = new InputStreamReader(con.getInputStream());
				BufferedReader breader = new BufferedReader(ireader);
				
				JSONParser parse = new JSONParser();
				JSONObject array = (JSONObject) parse.parse(breader);
				
				PacketResolutionDecoder decoder = new PacketResolutionDecoder(array);
				decoder.decode();
				
				String bind = (String)decoder.getResult();
				breader.close();
				ireader.close();
				con.disconnect();
				
				return bind;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static PacketFactory getFactory() {
		return factory;
	}
	
}
