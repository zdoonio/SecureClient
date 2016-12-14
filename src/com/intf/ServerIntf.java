package com.intf;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.ServerNotActiveException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public interface ServerIntf extends Remote {
	
	/*-----------------------------------------------------*/
	//													   //
	//				CREATED BY DOMINIK ZEDD				   //
	//					Copyright © 2016				   //
	//													   //
	/*-----------------------------------------------------*/
	
	public String getMessage1() throws RemoteException;

	public String getMessage2() throws RemoteException;
	
	public void sendMessage1(String message) throws RemoteException;
	
	public void sendMessage2(String message) throws RemoteException;
	
	public void sendFlagState(int flag) throws RemoteException;
	
	public void sendTargetName(String name) throws RemoteException;
	
	public void sendClientName(String name) throws RemoteException;
	
	public ArrayList<String> getConnectedUser() throws RemoteException;
	
	public String getTargetName() throws RemoteException, ServerNotActiveException;
	
	public int getFlagState() throws RemoteException;

	public char Login(String login, char[] password) throws RemoteException ,NoSuchAlgorithmException, InvalidKeySpecException;

	public void setZalogowano(boolean zalogowano) throws RemoteException;

	public boolean isLogedIn() throws RemoteException;

}