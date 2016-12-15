package com.intf;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.ServerNotActiveException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public interface ServerIntf extends Remote {
	
	/*-----------------------------------------------------*/
	//													   //
	//				CREATED BY DOMINIK ZEDD				   //
	//					Copyright © 2016				   //
	//													   //
	/*-----------------------------------------------------*/
	
	public byte[] getMessage() throws RemoteException;
	
	public void sendMessage(byte[] message) throws RemoteException;
	
	public void sendFlagState(int flag) throws RemoteException;
	
	public void sendTargetName(String name) throws RemoteException;
	
	public void sendClientName(String name) throws RemoteException;
	
	public ArrayList<String> getConnectedUser() throws RemoteException;
	
	public String getTargetName() throws RemoteException, ServerNotActiveException;
	
	public int getFlagState() throws RemoteException;

	public char Login(String login, char[] password) throws RemoteException ,NoSuchAlgorithmException, InvalidKeySpecException;

	public void setZalogowano(boolean zalogowano) throws RemoteException;

	public boolean isLogedIn() throws RemoteException;

	public void sendPublicKey(PublicKey publicKey) throws RemoteException;
	
	PublicKey getPublicKey() throws RemoteException;

}