import java.io.*;
import java.security.*;

public class PasswordHasher {
    public static String[][] passwords = {
	{"navjeet","password"},
	{"john","123456"},
	{"fred","password123"},
	{"linda","notPassword"},
	{"kelly","asdfgh"}
    };
    public static void main(String[] args){
	try {
	    SecureRandom r = new SecureRandom();
	    File f = new File("passwords.csv");
	    f.createNewFile();
	    FileWriter fw = new FileWriter(f);
	    fw.append("user,salt,password\n");
	    for(int i=0;i<passwords.length;i++){
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] salt = new byte[16];
		r.nextBytes(salt);
		StringBuilder sb = new StringBuilder();
		for (byte b : salt) {
		    sb.append(String.format("%02X ", b));
		}
		String saltString= sb.toString();
		md.update(saltString.getBytes());
		byte[] saltedHashedPassword = md.digest(passwords[i][1].getBytes());
		sb = new StringBuilder();
		for (byte b : saltedHashedPassword) {
		    sb.append(String.format("%02X ", b));
		}

		String SHP = sb.toString();
		String entry = passwords[i][0]+","+
		               saltString+","+
		               SHP+"\n";
	        
		fw.append(entry);
	    }
	    fw.flush();
	    fw.close();
        } 
	catch (Exception e){
	    e.printStackTrace();
	}
    }
}
