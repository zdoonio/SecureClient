package com.standard;
import java.io.File;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.rmi.*;
import java.util.*;

import com.intf.ServerIntf;

public class Client {

	ServerIntf obj;
	//static final Scanner input = new Scanner(System.in);

	
	
	
	public boolean Loging(char[] password, String name, String ipadd) throws Exception {

		//ipadd = null;
		boolean zalogowano;
		

		obj = (ServerIntf) Naming
				.lookup("//"+ipadd+"/ServerSecure");

		//System.out.println("Witamy w banku, proszę się zalogować");
		obj.Login(name, password);
		obj.sendClientName(name);
		zalogowano = obj.isLogedIn();
			//name = input.next();
			//password = input.next();
		return zalogowano;
		
	}
	
	public String[] Refresh(String ipadd) throws RemoteException
	{
		try {
			obj = (ServerIntf) Naming
					.lookup("//"+ipadd+"/ServerSecure");
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotBoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String[] t = obj.getConnectedUser();
		return t;
	}
	
	
	
	//public boolean sendMessage()
}