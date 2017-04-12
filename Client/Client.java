import java.io.*;
import java.util.concurrent.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.net.ServerSocket;
import java.net.Socket;

public class Client {
    
    public static void main(String[] args) throws IOException {
	Socket socket = new Socket("localhost",16000);
	try{
	    Encryption e = new Encryption();
	    String commandLine;
	    BufferedReader console = new BufferedReader
		(new InputStreamReader(System.in));
	    DataOutputStream out = new DataOutputStream(
					socket.getOutputStream());
	    DataInputStream in = new DataInputStream(
				      socket.getInputStream());
	    
	    boolean valid = false;
	    byte[] key = generateSharedKey(socket);
	    
	    
	    while(true) {
		System.out.print("Enter Username(or 'quit' to exit): ");
		String userName = console.readLine();
		if(userName.equals("quit")){
		    out.write(e.encryptData(e.longToBytes(-1),key,false));
		    valid = false;
		    break;
		}
			
		System.out.print("Enter Password: ");
		String password = console.readLine();
		byte[] len = e.longToBytes((long)userName.length());
		out.write(e.encryptData(len, key, false));
		byte[] name = e.padData(userName.getBytes(),userName.length());
		out.write(e.encryptData(name,key, false));
		len = e.longToBytes((long)password.length());
		out.write(e.encryptData(len,key, false));
		byte[] pass = e.padData(password.getBytes(),password.length());
		out.write(e.encryptData(pass,key,false));

		in.read(len,0,8);
		len = e.encryptData(len,key,true);
		if(e.bytesToLong(len) >= 0){
		    valid = true;
		    break;
		}else {
		    System.out.println("Error: incorrect username or password");
		}
	    }
	    
	    //valid=true;
	    while(valid){
		System.out.print("client_shell>");
		commandLine = console.readLine();
		//if just a return, loop
		if (commandLine.equals("")){
		    continue;
		}
		if(commandLine.equals("help")){
		    System.out.println("\n   Commands:\n"+
			  "     help :           list commands\n"+
			  "     get \"filename\" : retrieve file from server\n"+
			  "     quit :           exit program\n");
		    continue;
		}
		if(commandLine.equals("quit")){
		    out.write(e.encryptData(e.longToBytes(-1),key,false));
		    break;
		} 
		String[] command = commandLine.split(" ");
		if(command[0].equals("get")){
		    String filename = command[1];
		    long length = filename.length();
		    byte[] len = e.longToBytes(length);
		    byte[] message = e.padData(filename.getBytes(),(int)length);
		    out.write(e.encryptData(len,key,false));
		    out.write(e.encryptData(message,key,false));
		    in.read(len,0,8);
		    len = e.encryptData(len,key,true);
		    //negative length means no file
		    if(e.bytesToLong(len)>=0){
			byte[] cipher=new byte[e.roundUp((int)e.bytesToLong(len))];
			byte[] file=new byte[(int)e.bytesToLong(len)];
			in.read(cipher,0,cipher.length);
			cipher = e.encryptData(cipher,key,true);
		        for(int i=0;i<(int)e.bytesToLong(len);i++){
			    file[i]=cipher[i];
			}
			FileOutputStream fos = new FileOutputStream(filename);
			fos.write(file);
			fos.close();
			continue;
		    }
		    System.out.println("Error: File Not Found");
		    continue;
		}

		System.out.println("Command not recognized."
		     +" Type help for a list of commands");
	    }//end while

	}catch(Exception e){
	    System.out.println(e);
	    System.exit(1);
	} finally {
	    socket.close();
	}
    }   

    public static byte[] generateSharedKey(Socket socket) throws Exception{
	ObjectOutputStream obOut = new ObjectOutputStream(
				   socket.getOutputStream());
	ObjectInputStream obIn = new ObjectInputStream(
				 socket.getInputStream());
	//key agreement example
	KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
	kpg.initialize(512);
	KeyAgreement ka = KeyAgreement.getInstance("DH");
	KeyPair kp = kpg.generateKeyPair();
	//initialize with private key
	ka.init(kp.getPrivate());
	Object obj = obIn.readObject();
	PublicKey sk = (PublicKey) obj;
	obOut.writeObject(kp.getPublic());
	obOut.flush();
	//exchange public keys and do next phase
	ka.doPhase(sk, true);
	//generate secret keys
	SecretKey shared = ka.generateSecret("AES");
	byte[] sharedKey = new byte[16];
	    for(int i=0;i<16;i++){
		sharedKey[i] = shared.getEncoded()[i];
	    }
	    return sharedKey;
    }
}


