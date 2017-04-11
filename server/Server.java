import java.io.*;
import java.util.concurrent.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String args[]) throws IOException {
	int clientNumber = 0;
	ServerSocket listener = new ServerSocket(16000);
	try{
            while (true) {
                new ServiceClient(listener.accept(), clientNumber++).start();
            }
	    
	}finally{
	    listener.close();
	}
    }
    private static class ServiceClient extends Thread {
	private Socket socket;
	private int clientNumber;
	public ServiceClient(Socket socket, int ClientNumber){
	    this.socket = socket;
	    this.clientNumber = clientNumber;
	}
	public void run(){
	    try {
		socket.setSoTimeout(60000);
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
		    len = encryptData(len,key,true);
		    length = (int)bytesToLong(len);
		    //client disconnected
		    if(length < 0){
			valid = false;
			break;
		    }
		    rLength = roundUp(length);
		    byte[] cipherName = new byte[rLength];
		    byte[] name = new byte[length];
		    in.read(cipherName,0,cipherName.length);
		    cipherName = encryptData(cipherName,key,true); 
		    for(int i=0;i<length;i++){
			name[i]=cipherName[i];
		    }
		    
		    in.read(len,0,8);
		    len = encryptData(len,key,true);
		    length = (int)bytesToLong(len);
		    rLength = roundUp(length);
		    byte[] cipherPass = new byte[rLength];
		    byte[] pass = new byte[length];
		    in.read(cipherPass,0,cipherPass.length);
		    cipherPass = encryptData(cipherPass,key,true);
		    for(int i=0;i<length;i++){
			pass[i]=cipherPass[i];
		    }
		    String userName = new String(name);
		    String password = new String(pass);
		    //REPLACE WITH 
		    if(userName.equals("navjeet") && password.equals("navjeet")){
			valid=true;
			//send acknowledgement
			out.write(encryptData(longToBytes(1),key,false));
			break;
		    }else {
			out.write(encryptData(longToBytes(-1),key,false));
		    }
		}
		
		valid=true;
		
		while(valid){
		    in.read(len,0,8);
		    len = encryptData(len,key,true);
		    //negative length is a quit signal
		    if(bytesToLong(len)<0){
			break;
		    }
		    length =(int) bytesToLong(len);
		    rLength = roundUp(length);
		    byte[] cipher = new byte[rLength];
		    in.read(cipher, 0, cipher.length);
		    cipher = encryptData(cipher,key,true);
		    byte[] message = new byte[length];
		    for(int i=0;i<length;i++){
			message[i] = cipher[i];
		    }
		    String filename = new String(message);
		    File f = new File(filename);
		    if(f.exists() && !f.isDirectory()) { 
			out.write(encryptData(longToBytes(f.length()),key,false));
		        FileInputStream fis = new FileInputStream(f);
			byte[] file = new byte[(int)f.length()];
			fis.read(file);
			byte[] output = padData(file,file.length);
			out.write(encryptData(output,key,false));
		    }else{
			out.write(encryptData(longToBytes(-1),key,false));
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
    }
    public static byte[] generateSharedKey(Socket socket) throws Exception{
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
    /*
    public static File grabFile(String filename){

    }
    */
}
