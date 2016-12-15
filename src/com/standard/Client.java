package com.standard;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.server.ServerNotActiveException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.*;

import com.clients.ClientDH;
import com.clients.DecEncClient;
import com.intf.ServerIntf;
import com.security.Rsa;

public class Client {
	
	/*-----------------------------------------------------*/
	//													   //
	//				CREATED BY DOMINIK ZEDD				   //
	//					Copyright © 2016				   //
	//													   //
	/*-----------------------------------------------------*/
	ServerIntf obj;
	//static final Scanner input = new Scanner(System.in);
	public final int RSA = 0;
	public final int DiffieHelman = 1;
	
	private DecEncClient encdec;
	private static ObjectInputStream inputStream;
	
	public void lookUp(String ipadd) throws MalformedURLException, RemoteException, NotBoundException{
		obj = (ServerIntf) Naming
				.lookup("//"+ipadd+"/ServerSecure");
	}
	
	public boolean Loging(char[] password, String name, String ipadd) throws Exception {

		//ipadd = null;
		boolean LogedIn;
		

		lookUp(ipadd);

		//System.out.println("Witamy w banku, proszę się zalogować");
		obj.Login(name, password);
		obj.sendClientName(name);
		LogedIn = obj.isLogedIn();
			//name = input.next();
			//password = input.next();
		return LogedIn;
		
	}
	
	public ArrayList<String> Refresh(String ipadd) throws RemoteException, MalformedURLException, NotBoundException
	{
		lookUp(ipadd);
	
		ArrayList<String> t = obj.getConnectedUser();
		return t;
	}
	
	public String getClientName(String ipadd) throws RemoteException, MalformedURLException, NotBoundException, ServerNotActiveException{
		
			lookUp(ipadd);
			String t = obj.getTargetName();
		
		return t;
		
	}
	
	public int getFlag(String ipadd) throws RemoteException, MalformedURLException, NotBoundException{
			
		lookUp(ipadd);
		int i = obj.getFlagState();
		
		return i;
		
	}
	
	public PublicKey getPubKey(String ipadd) throws IOException, NotBoundException{
		lookUp(ipadd);
		
		PublicKey p = obj.getPublicKey();
		System.out.println("This is geted Public Key: "+ p);
		return p;
		
	}
	
	public void sendAgreementInfo(int globalFlag, String name, String ipadd) throws MalformedURLException, RemoteException, NotBoundException {
		// TODO Auto-generated method stub
		lookUp(ipadd);
		
		obj.sendFlagState(globalFlag);
		obj.sendTargetName(name);
	}
	
	public void sendPubKey(String ipadd,int flag) throws FileNotFoundException, IOException, ClassNotFoundException, NotBoundException {
		  String name = MainAppGUI.getClientName();
		  if(flag == 0){
		  inputStream = new ObjectInputStream(new FileInputStream("keysrsa/"+name+"public.key"));
	      final PublicKey publicKey = (PublicKey) inputStream.readObject();
	      lookUp(ipadd);
	      System.out.println("This is sended Public Key: "+ publicKey);
		
		obj.sendPublicKey(publicKey);
		  }
		  
		  if(flag == 1){
			  inputStream = new ObjectInputStream(new FileInputStream("keysdh/pubkeydh"+name+".key"));
		      final PublicKey publicKey = (PublicKey) inputStream.readObject();
		      lookUp(ipadd);
		      System.out.println("This is sended Public Key: "+ publicKey);
			obj.sendPublicKey(publicKey);
		  }
		
	}
	
	public void sendMessage(String ipadd, byte[] msg) throws MalformedURLException, RemoteException, NotBoundException{
		lookUp(ipadd);
		
		obj.sendMessage(msg);
	}
	
	public byte[] getMessage(String ipadd) throws MalformedURLException, RemoteException, NotBoundException{
		lookUp(ipadd);
		byte[] m = obj.getMessage();
		return m;
	}
	

	
	public void Init(int choose, String name) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		switch (choose) {

		case 0:
		
			break;

		case 1:
			//encdec = new ClientDH(name);
			break;

		case 2:

			break;

		case 3:

			break;

		case 4:

			break;

		}
	}

	
	
	
	
	//public boolean sendMessage()
}