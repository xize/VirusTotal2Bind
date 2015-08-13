package me.xephore.virustotal2bind;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public interface GuiApi {
	
	/**
	 * returns the sent button
	 * 
	 * @author xize
	 * @return JButton
	 */
	public JButton getButton();
	
	/**
	 * returns the field where you put the malicious url in
	 * 
	 * @author xize
	 * @return JTextField
	 */
	public JTextField getTextField();
	
	/**
	 * the non editable text area where the converted bind list will appear
	 * 
	 * @author xize
	 * @return JTextArea
	 */
	public JTextArea getTextArea();
	
	/**
	 * the status of progress
	 * 
	 * @author xize
	 * @return JLabel
	 */
	public JLabel getStatus();
	
	/**
	 * returns the amount of detections being found globally
	 * 
	 * @author xize
	 * @return JLabel
	 */
	public JLabel getDetections();
	
	/**
	 * returns the selection box of the type zone given in
	 * 
	 * @author xize
	 * @return JComboBox
	 */
	public JComboBox getZoneTypeSelection();
	
	/**
	 * returns the zone output data
	 * 
	 * @author xize
	 * @return JTextField
	 */
	public JTextArea getZoneOutputData();

}
