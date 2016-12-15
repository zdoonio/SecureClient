package com.standard;

import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageIO;
import javax.swing.*;

import com.security.DiffieHellman;
import com.security.IvGenerator;
import com.security.Rsa;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.ServerNotActiveException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class ClientGUI extends JFrame implements ActionListener {
	
	/*-----------------------------------------------------*/
	//													   //
	//				CREATED BY DOMINIK ZEDD				   //
	//					Copyright © 2016				   //
	//													   //
	/*-----------------------------------------------------*/
	private JButton bencrypt, bexit, bdecrypt, bsend, bok, brefresh, bserverinfo, bgenkeys, bsendpubkey, bgetpubkey, bgetlastmsg;
	private static JComboBox<String> securityChooser;
	private JComboBox<String> pubkeyChooser;
	private JComboBox<String> privkeyChooser;
	private static JComboBox<String> destiChooser;
	private JLabel lname, ldestiUser, lpubkey, lprivkey, lsecu;
	private JTextArea messageText, plainText;
	private JOptionPane pcommunication;

	private DiffieHellman df;
	private Rsa rsa;
	private IvParameterSpec iv;
	private static Client client;
	private static int globalFlag = 0;
	private static String targetName = null;
	private static boolean flagState = false;
	private static String name;
	private static String ipadd;
	private String msgFromClient;
	private PublicKey pubkey = null;
	private byte[] CipherText,PlainText;
	private int blocksize = IvGenerator.AES_BLOCK_SIZE;

	/**
	 * 
	 */
	private static final long serialVersionUID = 188489L;

	public ClientGUI() throws IOException {
		
		super("Secured Chat Client v0.3");
		// WINDOW INIT
		setSize(500, 600);
		name = MainAppGUI.getClientName();
		ipadd = MainAppGUI.getIpName();
		iv = IvGenerator.generateIV(blocksize);
		setName("Secured Chat Client v0.3");
		setLayout(null);
		setResizable(false);
		// BUTTONS INIT
		bencrypt = new JButton("ENCRYPT");
		bexit = new JButton("EXIT");
		bencrypt.setBounds(20, 250 + 120, 150, 30);
		bexit.setBounds(180, 320 + 120, 150, 30);
		add(bencrypt);
		add(bexit);
		bencrypt.addActionListener(this);
		bexit.addActionListener(this);
		bdecrypt = new JButton("DECRYPT");
		bdecrypt.setBounds(190 + 150, 250 + 120, 150, 30);
		add(bdecrypt);
		bdecrypt.addActionListener(this);
		bsend = new JButton("SEND");
		bsend.setBounds(180, 250 + 120, 150, 30);
		add(bsend);
		bsend.addActionListener(this);
		bok = new JButton("OK");
		bok.setBounds(345, 50, 150, 50);
		add(bok);
		bok.addActionListener(this);
		brefresh = new JButton("REFRESH");
		brefresh.setBounds(345, 20, 150, 20);
		add(brefresh);
		brefresh.addActionListener(this);
		bserverinfo = new JButton("USER INFO");
		bserverinfo.setBounds(180, 140, 150, 30);
		add(bserverinfo);
		bserverinfo.addActionListener(this);
		bgenkeys = new JButton("GEN KEYS");
		bgenkeys.setBounds(180, 180, 150, 30);
		add(bgenkeys);
		bgenkeys.addActionListener(this);
		bsendpubkey= new JButton("SEND PUBKEY");
		bsendpubkey.setBounds(180, 220, 150, 30);
		add(bsendpubkey);
		bsendpubkey.addActionListener(this);
		bgetpubkey= new JButton("GET PUBKEY");
		bgetpubkey.setBounds(180, 260, 150, 30);
		add(bgetpubkey);
		bgetpubkey.addActionListener(this);
		bgetlastmsg= new JButton("GET MSG");
		bgetlastmsg.setBounds(180, 300, 150, 30);
		add(bgetlastmsg);
		bgetlastmsg.addActionListener(this);

		// text field area init
		messageText = new JTextArea("");
		JScrollPane scrollPane1 = new JScrollPane(messageText);
		scrollPane1.setBounds(20, 120 + 30, 150, 200);
		add(scrollPane1);
		plainText = new JTextArea("");
		JScrollPane scrollPane2 = new JScrollPane(plainText);
		scrollPane2.setBounds(190 + 150, 120 + 30, 150, 200);
		add(scrollPane2);

		// label
		lname = new JLabel("CLIENT APP");
		lname.setBounds(200, 10, 150, 20);
		add(lname);
		ldestiUser = new JLabel("You name: "+name);
		ldestiUser.setBounds(20, 50, 200, 20);
		add(ldestiUser);
		lsecu = new JLabel("Choose key agreement");
		lsecu.setBounds(20, 80, 200, 20);
		add(lsecu);
		lpubkey = new JLabel("Decrypted message");
		lpubkey.setBounds(20, 115, 150, 20);
		add(lpubkey);
		lprivkey = new JLabel("Encrypted message");
		lprivkey.setBounds(340, 115, 150, 20);
		add(lprivkey);

		/*
		 * try{
		 * 
		 * }
		 * 
		 * catch (IOException e){ e.printStackTrace(); }
		 */

		// CHOOSER INIT
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
		 * pubkeyChooser = new JComboBox<String>();
		 * pubkeyChooser.setBounds(20,120,150,20); add(pubkeyChooser);
		 * pubkeyChooser.addActionListener(this);
		 * 
		 * privkeyChooser = new JComboBox<String>();
		 * privkeyChooser.setBounds(340,120,150,20); add(privkeyChooser);
		 * privkeyChooser.addActionListener(this);
		 */
		destiChooser = new JComboBox<String>();
		destiChooser.setBounds(190, 50, 150, 20);
		add(destiChooser);
		destiChooser.addActionListener(this);
	}
	



	public static void main(String[] args) throws IOException, NotBoundException, NoSuchAlgorithmException, NoSuchProviderException, ServerNotActiveException {
		// WINDOW OPEN
		ClientGUI mainWin = new ClientGUI();
		mainWin.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainWin.setVisible(true);
		while(true){
			if(targetName!=null){
				System.out.print("Getted Transmition");
				flagState = true;
			}
			if(flagState==true){
				Agreement();
				flagState=false;
			}
		}
	
	}

	public void CloseFrame() {
		super.dispose();
	}

	public void nothing() {

	}
	

	
	public void genKeys() throws RemoteException, MalformedURLException, NotBoundException, ServerNotActiveException, FileNotFoundException{
		
		switch (globalFlag) {

		case 0:
			rsa = new Rsa();
			rsa.generateKey(name);
			//String ipadd = MainAppGUI.getIpName();
			//targetName = client.getClientName(ipadd);
			break;
			

		case 1:
			df = new DiffieHellman();
			df.generateKeys();
			df.keySave(name);
			break;

		case 2:

			break;

		case 3:

			break;

		case 4:

			break;

		}
		
	}
	
	public static void Agreement() throws NotBoundException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ServerNotActiveException{
		//String ipadd = MainAppGUI.getIpName();
		targetName = null;
		int localFlag = 0;
		try {
			localFlag = client.getFlag(ipadd);
			targetName = client.getClientName(ipadd);
		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Target name:"+targetName+" localFlag "+localFlag);
		int option = JOptionPane.showConfirmDialog(null, targetName+" wanna recive the transmision!");
		if(option == JOptionPane.OK_OPTION){SetKeyAgreement(localFlag);}
		if(option == JOptionPane.NO_OPTION){}
		//if(option == JOptionPane.CANCEL_OPTION){}
		
	}
	
	public static void SetKeyAgreement(int flag) throws NotBoundException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
		//securityChooser.setEnabled(false);
		//destiChooser.setEnabled(false);
		switch (flag) {

		case 0:
		if(targetName == name){
				
			}
			else{
			String ipadd = MainAppGUI.getIpName();
			client.Init(flag, name);
			client.sendAgreementInfo(globalFlag,name,ipadd);
			}
			
			break;
			

		case 1:
			// df = new DiffieHellman();
			// df.generateKeys();
			//!!!!!!!!!!!!!
			if(targetName == name){
				
			}
			else{
			String ipadd = MainAppGUI.getIpName();
			client.Init(flag, name);
			client.sendAgreementInfo(globalFlag,name,ipadd);
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
	
	void flagSetter(){
		String security = securityChooser.getSelectedItem().toString();
		if (security.equals("RSA")) {
			globalFlag = 0;
			// System.out.println(flag);
		} else if (security.equals("Diffie-Helman")) {
			globalFlag = 1;
			// System.out.println(flag);
		} else if (security.equals("Merkle's Puzzles")) {
			globalFlag = 2;
			// System.out.println(flag);
		} else if (security.equals("TTP")) {
			globalFlag = 3;
			// System.out.println(flag);
		} else if (security.equals("PreDistributed")) {
			globalFlag = 4;
			// System.out.println(flag);
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		// System.out.println(new Date());
		Object o = e.getSource();
		ArrayList<String> t = new ArrayList<String>();
		// int choose = 0;
		if (o == brefresh) {
			String ipadd = MainAppGUI.getIpName();
			client = new Client();
			try {
				t = client.Refresh(ipadd);
			} catch (RemoteException | MalformedURLException | NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			for (String user : t) {
				destiChooser.addItem(user);
			}
			/*
			 * for (int i = 0; i < t.length; ++i) { destiChooser.addItem(t[i]);
			 * }
			 */
			return;
		}

		if (o == bencrypt) {
			switch(globalFlag){
				case 0:
			String msg = messageText.getText();
			CipherText = Rsa.encrypt(msg, pubkey);
			try {
				client.sendMessage(ipadd, CipherText);
			} catch (MalformedURLException | RemoteException
					| NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			System.out.println("This is encrypted: "+ CipherText);
				break;
				
				case 1:
					String msg1 = messageText.getText();
					CipherText = df.encrypt(msg1, iv);
				try {
					client.sendMessage(ipadd, CipherText);
				} catch (MalformedURLException | RemoteException
						| NotBoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				System.out.println("This is encrypted: "+ CipherText);
					break;
			}
			
			
			return;
		}

		if (o == bdecrypt) {
			try {
				PlainText = client.getMessage(ipadd);
			} catch (MalformedURLException | RemoteException
					| NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			ObjectInputStream inputStream = null;
			switch(globalFlag){
			case 0:
			try {
				
				inputStream = new ObjectInputStream(new FileInputStream("keysrsa/"+name+"private.key"));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		    PrivateKey privateKey = null;
			try {
				privateKey = (PrivateKey) inputStream.readObject();
			} catch (ClassNotFoundException | IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			msgFromClient = rsa.decrypt(PlainText, privateKey);
			System.out.println("This representation: "+ PlainText);
			System.out.println("This is decrypted: "+msgFromClient);
			break;
			
			case 1:
				df.decrypt(PlainText, iv);
				break;
			}
			return;
		}
		
		if (o == bgenkeys){
			try {
				genKeys();
			} catch (RemoteException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (MalformedURLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ServerNotActiveException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			return;
		}
		
		if (o == bsendpubkey){
			try {
				client.sendPubKey(ipadd,globalFlag);
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			return;
		}
		
		if (o == bgetpubkey){
			try {
				pubkey = client.getPubKey(ipadd);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			if(globalFlag == 1){
				df.receivePublicKey(pubkey);
				df.generateSharedSecret();
			}
			return;
		}

		if (o == bsend) {
			// String name = MainAppGUI.getClientName();
			// String ipadd = MainAppGUI.getIpName();
			// JOptionPane.showMessageDialog(null, name+":"+ipadd);
			byte[] send = CipherText;
			try {
				client.sendMessage(ipadd, send);
			} catch (MalformedURLException | RemoteException
					| NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			System.out.println("This is sended to server: "+send);
			return;
			
		}
		
		if (o == bgetlastmsg){
			
		
			plainText.setText(msgFromClient);
			return;
		}
		
		if (o == bserverinfo){
			System.out.print("Getted Transmition");
			String ipadd = MainAppGUI.getIpName();
			//targetName = client.getClientName(ipadd);
			try {
				targetName = client.getClientName(ipadd);
				System.out.println(targetName);
			} catch (RemoteException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (MalformedURLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ServerNotActiveException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
		}

		if (o == bok) {
			try {
				SetKeyAgreement(globalFlag);
			} catch (MalformedURLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (RemoteException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NotBoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchProviderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		
		

		if (o == securityChooser) {
			flagSetter();
		}

		if (o == destiChooser) {

		}
		
		
		if (o == bexit) {
			System.exit(0);
			CloseFrame();

			// ServerGUI server = new ServerGUI(1500);
			return;
		}

	}

}
