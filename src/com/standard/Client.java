package com.standard;
import java.io.File;
import java.io.PrintWriter;
import java.rmi.*;
import java.util.*;

import com.intf.ServerIntf;

public class Client {

	//static final Scanner input = new Scanner(System.in);

	
	
	
	public boolean Loging(char[] password, String name, String ipadd) throws Exception {

		//ipadd = null;
		boolean zalogowano;
		

		ServerIntf obj = (ServerIntf) Naming
				.lookup("//"+ipadd+"/ServerSecure");

		//System.out.println("Witamy w banku, proszę się zalogować");
		obj.Login(name, password);
		zalogowano = obj.isLogedIn();
			//name = input.next();
			//password = input.next();
		return zalogowano;
		
	}
	
	//public boolean sendMessage()
}