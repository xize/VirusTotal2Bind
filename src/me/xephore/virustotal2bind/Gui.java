package me.xephore.virustotal2bind;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.Insets;
import java.io.IOException;
import java.net.MalformedURLException;

import javax.imageio.ImageIO;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import me.xephore.virustotal2bind.events.ButtonEvent;
import me.xephore.virustotal2bind.events.SelectionEvent;
import me.xephore.virustotal2bind.events.TextFieldEvent;

public class Gui extends JFrame implements GuiApi {

	private static final long serialVersionUID = 3409741954230432504L;
	
	private JButton button;
	private JTextField textfield;
	private JTextArea textarea;
	private JLabel status;
	private JLabel detections;
	private JComboBox<String> select;
	private JTextArea file;
	
	public Gui(String title) {
		super(title);
	}
	
	public void buildContainer() {
		setResizable(false);
		setPreferredSize(new Dimension(700, 300));
		setMaximumSize(new Dimension(700, 300));
		setLocationRelativeTo(null);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		Image img = null;
		try {
			img = ImageIO.read(this.getClass().getResource("resources/scan.png"));
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		setIconImage(img);
		pack();
		setVisible(true);
	}
	
	
	public void createLayout() {
		
		setLayout(new BoxLayout(getContentPane(), BoxLayout.PAGE_AXIS));
		JPanel p1 = new JPanel();
		p1.setSize(getContentPane().getWidth(), 80);
		
		this.textfield = new JTextField("example.org");
		
		textfield.setBackground(Color.WHITE);
		textfield.setPreferredSize(new Dimension(200, 30));
		textfield.setHorizontalAlignment(JTextField.CENTER);
		
		this.button = new JButton("convert!");
		
		p1.add(textfield);
		p1.add(button);
		add(p1);
	
		JPanel p2 = new JPanel();
		this.textarea = new JTextArea();
		textarea.setLineWrap(true);
		textarea.setWrapStyleWord(true);
		textarea.setSize(new Dimension(500, 400));
		textarea.setRows(8);
		textarea.setEditable(false);
		JScrollPane scroll = new JScrollPane(textarea, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		p2.add(scroll);
		add(p2);
		
		JPanel p3 = new JPanel();
		p3.setSize(getContentPane().getWidth(), 40);
		this.status = new JLabel("status: idle...");
		this.detections = new JLabel("detections: 0");
		p3.add(status);
		p3.add(detections);
		add(p3);
		
		JPanel p4 = new JPanel();
		this.select = new JComboBox<String>(new String[] {
				"delegation-only",
				"forward",
				"hint",
				"in-view",
				"master",
				"redirect",
				"slave",
				"static-stub"
		});
		this.select.setSelectedIndex(4);
		this.select.setBackground(Color.WHITE);
		this.file = new JTextArea("type master;\nfile \"/etc/bind/blocked.db\";");
		this.file.setMargin(new Insets(3, 8, 3, 8));
		p4.add(select);
		p4.add(file);
		add(p4);
	}
	
	public void startListeners() {
		button.addActionListener(new ButtonEvent(this));
		textfield.addKeyListener(new TextFieldEvent(this));
		select.addActionListener(new SelectionEvent(this));
		
	}

	@Override
	public JButton getButton() {
		return button;
	}

	@Override
	public JTextField getTextField() {
		return textfield;
	}

	@Override
	public JTextArea getTextArea() {
		return textarea;
	}

	@Override
	public JLabel getStatus() {
		return status;
	}

	@Override
	public JLabel getDetections() {
		return detections;
	}

	@Override
	public JComboBox<String> getZoneTypeSelection() {
		return select;
	}

	@Override
	public JTextArea getZoneOutputData() {
		return file;
	}
	
	
}
