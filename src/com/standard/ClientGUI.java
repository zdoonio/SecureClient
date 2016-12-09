package com.standard;

import javax.imageio.ImageIO;
import javax.swing.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;


public class ClientGUI extends JFrame implements ActionListener {
	
	private JButton bencrypt, bexit, bdecrypt, bsend;
	private JComboBox<String> securityChooser,pubkeyChooser,privkeyChooser,destiChooser;
	private JLabel lname,ldestiUser,lpubkey,lprivkey;
	private JTextArea messageText,plainText;
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 188489L;
	

	public ClientGUI() throws IOException {
		super("Secured Chat Client v0.3");
		//WINDOW INIT
		setSize(500,600);
		setName("Secured Chat Client v0.3");
		setLayout(null);
		setResizable(false);
		//BUTTONS INIT
		bencrypt = new JButton ("ENCRYPT");
		bexit = new JButton ("EXIT");
		bencrypt.setBounds(20, 250+120, 150, 30);
		bexit.setBounds(180, 320+120, 150, 30);
		add(bencrypt);
		add(bexit);
		bencrypt.addActionListener(this);
		bexit.addActionListener(this);
		bdecrypt = new JButton ("DECRYPT");
		bdecrypt.setBounds(190+150,250+120,150,30);
		add(bdecrypt);
		bdecrypt.addActionListener(this);
		bsend = new JButton ("SEND");
		bsend.setBounds(180,250+120,150,30);
		add(bsend);
		bsend.addActionListener(this);
		
		//text field area init
		messageText = new JTextArea("");
		JScrollPane scrollPane1 = new JScrollPane(messageText);
		scrollPane1.setBounds(20, 120+30, 150, 200);
		add(scrollPane1);
		plainText = new JTextArea("");
		JScrollPane scrollPane2 = new JScrollPane(plainText);
		scrollPane2.setBounds(190+150, 120+30, 150, 200);
		add(scrollPane2);
		
		
		//label
		lname = new JLabel("CLIENT APP");
		lname.setBounds(200,10,150,20);
		add(lname);
		ldestiUser = new JLabel("Destination User");
		ldestiUser.setBounds(40,50,150,20);
		add(ldestiUser);
		lpubkey = new JLabel("Choose Public Key");
		lpubkey.setBounds(20,100,150,20);
		add(lpubkey);
		lprivkey = new JLabel("Choose Private Key");
		lprivkey.setBounds(340,100,150,20);
		add(lprivkey);
		
		
		/*
		try{
			
		}
		
		catch (IOException e){
			e.printStackTrace();
		} */
		
		//CHOOSER INIT
		securityChooser = new JComboBox<String>();
		securityChooser.setBounds(180, 280+30, 150, 20);
		securityChooser.addItem("RSA");
		securityChooser.addItem("Diffie-Helman");
		securityChooser.addItem("Merkle Puzzel's");
		securityChooser.addItem("TTP");
		securityChooser.addItem("PreDistributed");
		add(securityChooser);
		securityChooser.addActionListener(this);
		
		pubkeyChooser = new JComboBox<String>();
		pubkeyChooser.setBounds(20,120,150,20);
		add(pubkeyChooser);
		pubkeyChooser.addActionListener(this);
		
		privkeyChooser = new JComboBox<String>();
		privkeyChooser.setBounds(340,120,150,20);
		add(privkeyChooser);
		privkeyChooser.addActionListener(this);
		
		destiChooser = new JComboBox<String>();
		destiChooser.setBounds(180,50,150,20);
		add(destiChooser);
		destiChooser.addActionListener(this);
	}
	
	public static void main(String[] args) throws IOException {
		//WINDOW OPEN
		ClientGUI mainWin  = new ClientGUI();
		mainWin.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainWin.setVisible(true);
		
	}
	
	public void CloseFrame(){
	    super.dispose();
	}
	
	

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		//System.out.println(new Date());
			Object o = e.getSource();
			
			if(o == bencrypt ){
		
			
			return;
			}
			
			if(o == bdecrypt ){
				
				
				return;
				}
			
			if(o == bsend ){
				
				
				return;
				}
			
			if(o == bexit){
				System.exit(0);
				CloseFrame();
				
			//ServerGUI server = new ServerGUI(1500);
			return;
			}
			
			
		
		
	}

	
}
