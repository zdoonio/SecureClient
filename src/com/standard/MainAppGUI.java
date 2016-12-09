package com.standard;

import javax.swing.*;

import java.awt.event.*;
import java.io.IOException;

public class MainAppGUI extends JFrame implements ActionListener {

	private JButton blogin, bcancel;
	private JLabel lnameapp, lname, lpw, lip, lport;
	private JTextField tname, tip, tport;
	private JPasswordField tpw;
	private ClientGUI client;
	/**
	 * 
	 */
	private static final long serialVersionUID = 188889L;

	public MainAppGUI() throws IOException {
		super("Login");
		// WINDOW INIT
		setSize(500, 250);
		setName("Login Form");
		setLayout(null);
		setResizable(false);
		// BUTTONS INIT
		blogin = new JButton("LOGIN");
		bcancel = new JButton("CANCEL");
		blogin.setBounds(60, 180, 150, 20);
		bcancel.setBounds(240, 180, 150, 20);
		add(blogin);
		add(bcancel);
		blogin.addActionListener(this);
		bcancel.addActionListener(this);

		// label
		lnameapp = new JLabel("Login");
		lnameapp.setBounds(120, 10, 150, 20);
		add(lnameapp);
		// TEXTFIELD INIT
		tname = new JTextField("");
		tname.setBounds(190, 60, 150, 20);
		add(tname);
		tpw = new JPasswordField("");
		tpw.setBounds(190, 90, 150, 20);
		add(tpw);
		tip = new JTextField("localhost");
		tip.setBounds(190, 120, 150, 20);
		add(tip);
		tport = new JTextField("1500");
		tport.setBounds(190, 150, 150, 20);
		add(tport);

		// label
		lnameapp = new JLabel("To Server");
		lnameapp.setBounds(190, 10, 150, 20);
		add(lnameapp);
		lname = new JLabel("User Name");
		lname.setBounds(100, 60, 150, 20);
		add(lname);
		lpw = new JLabel("Password");
		lpw.setBounds(100, 90, 150, 20);
		add(lpw);
		lip = new JLabel("Ip Server");
		lip.setBounds(100, 120, 150, 20);
		add(lip);
		lport = new JLabel("Port");
		lport.setBounds(100, 150, 150, 20);
		add(lport);

		/*
		 * try{
		 * 
		 * }
		 * 
		 * catch (IOException e){ e.printStackTrace(); }
		 */

		/*
		 * //CHOOSER INIT securityChooser = new JComboBox();
		 * securityChooser.setBounds(20, 80, 150, 20);
		 * securityChooser.addItem("RSA");
		 * securityChooser.addItem("Diffie-Helman");
		 * securityChooser.addItem("Merkle Puzzel's");
		 * securityChooser.addItem("TTP");
		 * securityChooser.addItem("PreDistributed"); add(securityChooser);
		 * securityChooser.addActionListener(this);
		 */
	}

	public static void main(String[] args) throws IOException {
		// WINDOW OPEN
		MainAppGUI mainWin = new MainAppGUI();
		mainWin.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainWin.setVisible(true);

	}

	public void CloseFrame() {
		super.dispose();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		// System.out.println(new Date());
		Object o = e.getSource();

		if (o == blogin) {

			try {
				client = new ClientGUI();
				client.setVisible(true);
				JOptionPane.showMessageDialog(null, "Login Successful!");
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			return;
		}

		if (o == bcancel) {
			System.exit(0);
			CloseFrame();

			// ServerGUI server = new ServerGUI(1500);
			return;
		}

	}

}
