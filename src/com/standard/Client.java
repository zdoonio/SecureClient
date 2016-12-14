package com.standard;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.rmi.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
	
	
	
	public boolean Loging(char[] password, String name, String ipadd) throws Exception {

		//ipadd = null;
		boolean LogedIn;
		

		obj = (ServerIntf) Naming
				.lookup("//"+ipadd+"/ServerSecure");

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
			obj = (ServerIntf) Naming
					.lookup("//"+ipadd+"/ServerSecure");
	
		ArrayList<String> t = obj.getConnectedUser();
		return t;
	}
	
	public String getClientName(String ipadd) throws RemoteException, MalformedURLException, NotBoundException{
		
			obj = (ServerIntf) Naming
					.lookup("//"+ipadd+"/ServerSecure");
			String t = obj.getTargetName();
		
		return t;
		
	}
	
	public int getFlag(String ipadd) throws RemoteException, MalformedURLException, NotBoundException{
			
		obj = (ServerIntf) Naming
					.lookup("//"+ipadd+"/ServerSecure");
		int i = obj.getFlagState();
		
		return i;
		
	}
	
	public void sendAgreementInfo(int globalFlag, String name, String ipadd) throws MalformedURLException, RemoteException, NotBoundException {
		// TODO Auto-generated method stub
		obj = (ServerIntf) Naming
				.lookup("//"+ipadd+"/ServerSecure");
		
		obj.sendFlagState(globalFlag);
		obj.sendTargetName(name);
	}
	
	public void Init(int choose, String name) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		switch (choose) {

		case 0:
		
			break;

		case 1:
			encdec = new ClientDH(name);
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