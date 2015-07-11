package me.xephore.virustotal2bind.packets;

public interface Decoder {
	
	/**
	 * decodes the data
	 * 
	 * @author xize
	 */
	public void decode();

	/**
	 * returns the result what is decoded
	 * 
	 * @author xize
	 * @return Object
	 */
	public Object getResult();
	
}
