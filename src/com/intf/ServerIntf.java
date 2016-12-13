package com.intf;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface ServerIntf extends Remote {

	public String getMessage1() throws RemoteException;

	public String getMessage2() throws RemoteException;
	
	public void sendMessage1(String message) throws RemoteException;
	
	public void sendMessage2(String message) throws RemoteException;

	public void sendClientName(String name) throws RemoteException;
	
	public String[] getConnectedUser() throws RemoteException;

	public char Login(String login, char[] password) throws RemoteException ,NoSuchAlgorithmException, InvalidKeySpecException;

	public void setZalogowano(boolean zalogowano) throws RemoteException;

	public boolean isLogedIn() throws RemoteException;

}