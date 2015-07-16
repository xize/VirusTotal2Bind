package me.xephore.virustotal2bind.packets;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import me.xephore.virustotal2bind.GuiApi;
import me.xephore.virustotal2bind.enums.AppType;
import me.xephore.virustotal2bind.enums.PacketType;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class AppContainer extends PacketContainer {

	public AppContainer(GuiApi gui, Packet packet) {
		super(gui, packet);
	}

	@Override
	public AppType getType() {
		return AppType.APPLICATION;
	}

	@Override
	public String[] execute() {
		try {
			String[] data = new String[2];

			if(getPacket().getType() == PacketType.DOMAIN) {
				URL url = new URL(getPacket().getType().getProvider().toString() + "?domain="+getPacket().getParams()[0] + "&apikey="+getPacket().getParams()[1]);
				HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
				con.setRequestMethod("GET");
				con.setDoOutput(true);
				InputStreamReader ireader = new InputStreamReader(con.getInputStream());
				BufferedReader breader = new BufferedReader(ireader);

				JSONParser parse = new JSONParser();
				JSONObject array = (JSONObject) parse.parse(breader);

				Decoder decoder = new PacketResolutionDecoder(array, getPacket().getParams()[0]);
				decoder.decode();

				Decoder decoder_detections = new PacketDetectionDecoder(array);
				decoder_detections.decode();

				String bind = (String)decoder.getResult();
				String detected = (String)decoder_detections.getResult();

				breader.close();
				ireader.close();
				con.disconnect();

				data[0] = bind;
				data[1] = detected;
			} else if(getPacket().getType() == PacketType.IP) {

				URL url = new URL(getPacket().getType().getProvider().toString() + "?ip="+getPacket().getParams()[0] + "&apikey="+getPacket().getParams()[1]);
				HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
				con.setRequestMethod("GET");

				InputStreamReader ireader = new InputStreamReader(con.getInputStream());
				BufferedReader breader = new BufferedReader(ireader);

				JSONParser parse = new JSONParser();
				JSONObject array = (JSONObject) parse.parse(breader);

				PacketResolutionDecoder decoder = new PacketResolutionDecoder(array, getPacket().getParams()[0]);
				decoder.decode();

				Decoder decoder_detections = new PacketDetectionDecoder(array);
				decoder_detections.decode();

				String bind = (String)decoder.getResult();
				String detected = (String)decoder_detections.getResult();
				breader.close();
				ireader.close();
				con.disconnect();

				data[0] = bind;
				data[1] = detected;
			}
			return data;
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
