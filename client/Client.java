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
	    
	    String commandLine;
	    BufferedReader console = new BufferedReader
		(new InputStreamReader(System.in));
	    DataOutputStream out = new DataOutputStream(
					socket.getOutputStream());
	    DataInputStream in = new DataInputStream(
				      socket.getInputStream());
	    
	    boolean valid = false;
	    byte[] key = generateSharedKey(socket);
	    /*
	    while(true) {
		System.out.println("Enter Username(or 'quit' to exit): ");
		String userName = console.readLine();
		if(userName.equals("quit")){
		    valid = false;
		    break;
		}
			
		System.out.println("Enter Password: ");
		String password = console.readLine();
		dOut.writeInt(userName.length());
		dOut.write(userName.getBytes());
		dOut.writeInt(password.length());
		dOut.write(password.getBytes());
		if(dIn.readInt() > 0){
		    valid = true;
		    break;
		}
	    }
	    */
	    valid=true;
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
		    out.write(encryptData(longToBytes(-1),key,false));
		    break;
		} 
		String[] command = commandLine.split(" ");
		if(command[0].equals("get")){
		    String filename = command[1];
		    long length = filename.length();
		    byte[] len = longToBytes(length);
		    byte[] message = padData(filename.getBytes(),(int)length);
		    out.write(encryptData(len,key,false));
		    out.write(encryptData(message,key,false));
		    in.read(len,0,8);
		    len = encryptData(len,key,true);
		    //negative length means no file
		    if(bytesToLong(len)>=0){
			byte[] cipher=new byte[roundUp((int)bytesToLong(len))];
			byte[] file=new byte[(int)bytesToLong(len)];
			in.read(cipher,0,cipher.length);
			cipher = encryptData(cipher,key,true);
		        for(int i=0;i<(int)bytesToLong(len);i++){
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
    public static byte[] encryptData(byte[] buff,byte[] key,boolean decrypt){
	//Encryption routine
	Encryption e = new Encryption();
	System.loadLibrary("encrypt");
	System.loadLibrary("decrypt");
	int[] rawKey = byteToInt(key);
	int[] input = byteToInt(buff);
	int[] result = new int[input.length];
	for(int i=0;i<input.length-1;i+=2){
	    int[] blockIn = new int[2];
	    int[] blockOut = new int[2];
	    blockIn[0] = input[i];
	    blockIn[1] = input[i+1];
	    if(decrypt){
		blockOut = e.decrypt(blockIn,rawKey);
	    }else{
		blockOut = e.encrypt(blockIn, rawKey);
	    }
	    result[i] = blockOut[0];
	    result[i+1] = blockOut[1];
	}
	return intToByte(result);
    }
				       
    public static int[] byteToInt(byte[] array){
	ByteBuffer byteBuffer = ByteBuffer.wrap(array);
	IntBuffer intBuffer = byteBuffer.asIntBuffer();
	int[] result = new int[intBuffer.capacity()];
	intBuffer.get(result);
	return result;
    }
    public static byte[] intToByte(int[] array){
	ByteBuffer byteBuffer = ByteBuffer.allocate(array.length * 4);        
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        intBuffer.put(array);
        byte[] result = byteBuffer.array();
	return result;
    }

   public static byte[] longToBytes(long x) {
	ByteBuffer buffer = ByteBuffer.allocate(8);
	buffer.putLong(x);
	return buffer.array();
    }
    
    public static long bytesToLong(byte[] bytes) {
	ByteBuffer buffer = ByteBuffer.allocate(8);
	buffer.put(bytes);
	buffer.flip();//need flip 
	return buffer.getLong();
    }

    public static int roundUp(int n) {
	return (int)Math.ceil((double)n/8.00)*8;
    }
    public static byte[] padData(byte[] data, int length){
	int rounded = roundUp(length);
	byte[] padded = new byte[rounded];
	for(int i=0;i<rounded;i++){
	    if(i<(int)length){
		padded[i] = data[i];
	    }else{
		padded[i]=0;
	    }
	}
	return padded;
    }
 

}

