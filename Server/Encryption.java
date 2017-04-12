import java.nio.*;

public class Encryption { 
    private native int[] encrypt(int[] v, int[] k);
    private native int[] decrypt(int[] v, int[] k);

  
    public byte[] encryptData(byte[] buff,byte[] key,boolean decrypt){
	//Encryption routine
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
		blockOut = decrypt(blockIn,rawKey);
	    }else{
		blockOut = encrypt(blockIn, rawKey);
	    }
	    result[i] = blockOut[0];
	    result[i+1] = blockOut[1];
	}
	return intToByte(result);
    }

				       
    public int[] byteToInt(byte[] array){
	ByteBuffer byteBuffer = ByteBuffer.wrap(array);
	IntBuffer intBuffer = byteBuffer.asIntBuffer();
	int[] result = new int[intBuffer.capacity()];
	intBuffer.get(result);
	return result;
    }
    public byte[] intToByte(int[] array){
	ByteBuffer byteBuffer = ByteBuffer.allocate(array.length * 4);        
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        intBuffer.put(array);
        byte[] result = byteBuffer.array();
	return result;
    }

    public byte[] longToBytes(long x) {
	ByteBuffer buffer = ByteBuffer.allocate(8);
	buffer.putLong(x);
	return buffer.array();
    }
    
    public long bytesToLong(byte[] bytes) {
	ByteBuffer buffer = ByteBuffer.allocate(8);
	buffer.put(bytes);
	buffer.flip();//need flip 
	return buffer.getLong();
    }

    public int roundUp(int n) {
	return (int)Math.ceil((double)n/8.00)*8;
    }
    public byte[] padData(byte[] data, int length){
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
