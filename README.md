# ECE422Project2

Compilation:
	Do the following in each Client and Server folders:
		$>javac *.java
		$>javah Encryption
		$>gcc -I/usr/java/default/include -I/usr/java/default/include/linux -shared -fpic -o libdecrypt.so libdecrypt.c 
		$>gcc -I/usr/java/default/include -I/usr/java/default/include/linux -shared -fpic -o libencrypt.so libencrypt.c 
		$>export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
		
Use PasswordGenerator in Server folder to create password.csv file required by the server.
