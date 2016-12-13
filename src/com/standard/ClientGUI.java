package com.standard;

import javax.imageio.ImageIO;
import javax.swing.*;

import com.security.DiffieHellman;
import com.security.Rsa;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;


public class ClientGUI extends JFrame implements ActionListener {
	
	private JButton bencrypt, bexit, bdecrypt, bsend, bok;
	private JComboBox<String> securityChooser,pubkeyChooser,privkeyChooser,destiChooser;
	private JLabel lname,ldestiUser,lpubkey,lprivkey,lsecu;
	private JTextArea messageText,plainText;
	
	private DiffieHellman df;
	private Rsa rsa;
	private Client client;
	private int flag = 0;
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
		bok = new JButton ("OK");
		bok.setBounds(345,50,150,50);
		add(bok);
		bok.addActionListener(this);
		
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
		ldestiUser.setBounds(20,50,200,20);
		add(ldestiUser);
		lsecu = new JLabel("Choose key agreement");
		lsecu.setBounds(20,80,200,20);
		add(lsecu);
		lpubkey = new JLabel("Decrypted message");
		lpubkey.setBounds(20,115,150,20);
		add(lpubkey);
		lprivkey = new JLabel("Encrypted message");
		lprivkey.setBounds(340,115,150,20);
		add(lprivkey);
		
		
		/*
		try{
			
		}
		
		catch (IOException e){
			e.printStackTrace();
		} */
		
		//CHOOSER INIT
		securityChooser = new JComboBox<String>();
		securityChooser.setBounds(190, 80, 150, 20);
		securityChooser.addItem("RSA");
		securityChooser.addItem("Diffie-Helman");
		securityChooser.addItem("Merkle's Puzzles");
		securityChooser.addItem("TTP");
		securityChooser.addItem("PreDistributed");
		add(securityChooser);
		securityChooser.addActionListener(this);
		/*
		pubkeyChooser = new JComboBox<String>();
		pubkeyChooser.setBounds(20,120,150,20);
		add(pubkeyChooser);
		pubkeyChooser.addActionListener(this);
		
		privkeyChooser = new JComboBox<String>();
		privkeyChooser.setBounds(340,120,150,20);
		add(privkeyChooser);
		privkeyChooser.addActionListener(this);
		*/
		destiChooser = new JComboBox<String>();
		destiChooser.setBounds(190,50,150,20);
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
        
        public void nothing() {
        
        }
	
	

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		//System.out.println(new Date());
			Object o = e.getSource();
			
			//int choose = 0;
			
			if(o == bencrypt ){
		
			
			return;
			}
			
			if(o == bdecrypt ){
				
				
				return;
				}
			
			if(o == bsend ){
				
				
				return;
				}
			
			if(o == bok){
				securityChooser.setEnabled(false);
				//destiChooser.setEnabled(false);
				switch(flag){
				
				case 0:
					rsa = new Rsa();
					rsa.generateKey();
					break;
					
				case 1:
					df = new DiffieHellman();
					df.generateKeys();
					try {
						df.keySave("Dominik");
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					break;
					
				case 2:
				
					break;
				
				case 3:
					
					break;
				
				case 4:
					
					break;
					
				
				}
				return;
				}
			
			if(o == securityChooser){
				String security = securityChooser.getSelectedItem().toString();
				if(security.equals("RSA")){
					flag = 0;
					//System.out.println(flag);
				}
				else if(security.equals("Diffie-Helman")){
					flag = 1;
					//System.out.println(flag);
				}
				else if(security.equals("Merkle's Puzzles")){
					flag = 2;
					//System.out.println(flag);
				}
				else if(security.equals("TTP")){
					flag = 3;
					//System.out.println(flag);
				}
				else if(security.equals("PreDistributed")){
					flag = 4;
					//System.out.println(flag);
				}
			}
			
			if(o == destiChooser){
				
			}
			
			if(o == bexit){
				System.exit(0);
				CloseFrame();
				
			//ServerGUI server = new ServerGUI(1500);
			return;
			}
			
			
		
		
	}

	
}
