import java.io.*;
import java.util.concurrent.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.*;

import java.util.ArrayList;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String args[]) throws IOException {
	int clientNumber = 0;
	ServerSocket listener = new ServerSocket(16000);

	try{
	    ArrayList<String[]> passwords = loadPasswords("passwords.csv");
            while (true) {
                new ServiceClient(listener.accept(), clientNumber++,passwords).start();
            }
	    
	}catch(Exception e) {
	    System.out.println(e);
	}finally{
	    listener.close();
	}
    }
    private static class ServiceClient extends Thread {
	private Socket socket;
	private int clientNumber;
	private ArrayList<String[]> hashedPasswords;
	public ServiceClient(Socket socket, int ClientNumber, ArrayList<String[]> passwords){
	    this.socket = socket;
	    this.clientNumber = clientNumber;
	    this.hashedPasswords = passwords;
	}
	public void run(){
	    try {
		Encryption e = new Encryption();
		DataOutputStream out = new DataOutputStream(
					     socket.getOutputStream());
		DataInputStream in = new DataInputStream(
                                           socket.getInputStream());
		byte[] key = generateSharedKey(socket);
		boolean valid = false;
		int length=0;
		int rLength=0;
		byte[] len = new byte[8];
		
		while(true){
		    in.read(len,0,8);
		    len = e.encryptData(len,key,true);
		    length = (int)e.bytesToLong(len);
		    //client disconnected
		    if(length < 0){
			valid = false;
			break;
		    }
		    rLength = e.roundUp(length);
		    byte[] cipherName = new byte[rLength];
		    byte[] name = new byte[length];
		    in.read(cipherName,0,cipherName.length);
		    cipherName = e.encryptData(cipherName,key,true); 
		    for(int i=0;i<length;i++){
			name[i]=cipherName[i];
		    }
		    
		    in.read(len,0,8);
		    len = e.encryptData(len,key,true);
		    length = (int)e.bytesToLong(len);
		    rLength = e.roundUp(length);
		    byte[] cipherPass = new byte[rLength];
		    byte[] pass = new byte[length];
		    in.read(cipherPass,0,cipherPass.length);
		    cipherPass = e.encryptData(cipherPass,key,true);
		    for(int i=0;i<length;i++){
			pass[i]=cipherPass[i];
		    }
		    String userName = new String(name);
		    String password = new String(pass);
		    //REPLACE WITH 
		    if(authenticate(userName,password,hashedPasswords)){
			valid=true;
			//send acknowledgement
			out.write(e.encryptData(e.longToBytes(1),key,false));
			break;
		    }else {
			out.write(e.encryptData(e.longToBytes(-1),key,false));
		    }
		}
		
		valid=true;
		
		while(valid){
		    in.read(len,0,8);
		    len = e.encryptData(len,key,true);
		    //negative length is a quit signal
		    if(e.bytesToLong(len)<0){
			break;
		    }
		    length =(int) e.bytesToLong(len);
		    rLength = e.roundUp(length);
		    byte[] cipher = new byte[rLength];
		    in.read(cipher, 0, cipher.length);
		    cipher = e.encryptData(cipher,key,true);
		    byte[] message = new byte[length];
		    for(int i=0;i<length;i++){
			message[i] = cipher[i];
		    }
		    String filename = new String(message);
		    filename = "files/"+filename;
		    File f = new File(filename);
		    if(f.exists() && !f.isDirectory()) { 
			out.write(e.encryptData(e.longToBytes(f.length()),key,false));
		        FileInputStream fis = new FileInputStream(f);
			byte[] file = new byte[(int)f.length()];
			fis.read(file);
			byte[] output = e.padData(file,file.length);
			out.write(e.encryptData(output,key,false));
		    }else{
			out.write(e.encryptData(e.longToBytes(-1),key,false));
		    }
		}

            } catch (Exception e) {
                System.out.println("Error handling client# "
				   +clientNumber+": " + e);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.out.println("Couldn't close a socket, what's going on?");
                }
                System.out.println("Connection with client# " 
				   +clientNumber+" closed");
	    }
	}

	public boolean authenticate(String name, String password, ArrayList<String[]> passwords) throws NoSuchAlgorithmException{	    
	    for(int i=0;i<passwords.size();i++){
		if(name.equals(passwords.get(i)[0])){
		    MessageDigest md = MessageDigest.getInstance("SHA-256");
		    md.update(passwords.get(i)[1].getBytes());
		    byte[] saltedHashedPassword = md.digest(password.getBytes());
		    StringBuilder sb = new StringBuilder();
		    for (byte b : saltedHashedPassword) {
			sb.append(String.format("%02X ", b));
		    }
		    return passwords.get(i)[2].equals(sb.toString());
		}
	    }
	    return false;
	}
	public byte[] generateSharedKey(Socket socket) throws Exception{
	    ObjectOutputStream obOut = new ObjectOutputStream(socket.getOutputStream());
	    ObjectInputStream obIn = new ObjectInputStream(socket.getInputStream());
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
	    kpg.initialize(512);
	    KeyAgreement ka = KeyAgreement.getInstance("DH");
	    KeyPair kp = kpg.generateKeyPair();
	    ka.init(kp.getPrivate());
	    
	    obOut.writeObject(kp.getPublic());
	    obOut.flush();
	    Object obj = obIn.readObject();
	    PublicKey sk = (PublicKey) obj;
	    ka.doPhase(sk, true);
	    SecretKey shared = ka.generateSecret("AES");
	    byte[] sharedKey = new byte[16];
	    for(int i=0;i<16;i++){
		sharedKey[i] = shared.getEncoded()[i];
	    }
	    return sharedKey;
	}
	
    }
    
    public static ArrayList<String[]> loadPasswords(String fileName) throws Exception{
	ArrayList<String[]> passwords = new ArrayList<String[]>();
	BufferedReader fr = new BufferedReader(new FileReader(fileName));
	fr.readLine();
	String line = "";
	while((line = fr.readLine()) != null){
	    String[] entry = line.split(",");
	    if(entry.length > 0){
		passwords.add(entry);
	    }
	}
	return passwords;
    }

    
}
