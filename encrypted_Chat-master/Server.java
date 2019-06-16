/**
 * 
 * Server.java
 * 
 *
 * 
 *  
 *  Reference:
 *  http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html
 *  http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
 * 
 */


import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * 
 *  public class Server
 *
 *  Server program ce otvoriti socket na TCP portu 8002.
 *   Klijent  program ce uspostaviti vezu preko soketa i poslati sifrovane poruke na server.
 *  
 * 
 *  
 *  
 *  
 *  
 *  
 *
 */

public class Server {
	
	private ObjectOutputStream sOutput;
	private ObjectInputStream sInput;
	private Cipher keyDecipher;
	private Cipher ServerDecryptCipher;
	private Cipher ServerEncryptCipher;
	SecretKey AESKey;
	int i;
	byte[] input;
	private message m;
	int port;
	static String IV = "AAAAAAAAAAAAAAAA";
	message toSend;
	
	
	public Server(int port){
		this.port = port;
	}
	
	/*
	 * 
	 * 
	 * 					
	 * glavna metoda
     *                  ce napravi  RSA objekat za stvaranje privatnog kljuca spremiti ga kao "public.key"
     *                  i "private.key"   smesta  fajlove u istom direktorijumu.
     *
     *                                 Metod ce kreirati server objekt i metodu start ().
	 * 
	 * 					
	 * 
	 */
	
	public static void main(String[] args) throws IOException, GeneralSecurityException{
	//	RSA rsa = new RSA();
	//	rsa.createRSA();
		int port = 8002;
		Server server = new Server(port);
		server.start();
	}
	
	/*
	 *  pocetna metoda:
	 * 				  Poziva serverski prikljucak koji slusa za povezivanje  na TCP portu 8002.
	 *
	 * 				  Nakon uspostavljanja veze, pojedinacna veza ce se odvijati kao nezavisna nit.
	 * 
	 * 
	 * 					
	 */
	
	
	void start() throws IOException{
		ServerSocket serverSocket = new ServerSocket(port);
		System.out.print("Receiver listening on the port " + port + ".");
		Socket socket = serverSocket.accept();  // prihvatanje veze.
		clientThread t = new clientThread(socket);
		t.run();
		serverSocket.close();
	}
	
	
		/*
		 * klijentNit klasa.  
		 * 
         *      Radice se na soketima  uspostavljenoj od ulaza pocetne metode.
         *                Nit  ce pristupiti ulaznim i izlaznim tokovima soketa
         *                     da primite i šaljete poruke od klijenta.
		 */
	
	  class clientThread extends Thread{
		Socket socket;
		clientThread( Socket socket) throws IOException{
			this.socket = socket;
			sOutput = new ObjectOutputStream(socket.getOutputStream());
			sInput = new ObjectInputStream(socket.getInputStream());
			new listenFromClient().start();
			new sendToClient().start();
			}
	  }
	  
	  /*
		 * slusanje klijent klase. 
		 * 	
		 * Kontinuirano slusa dolazece poruke sa servera.
		 * Jednom primi poruku, desifruje  i stampa na konzoli servera
		 * 
		 * 
		 */
	  
		class listenFromClient extends Thread{
			
			public void run(){
				
			while(true){
			try {
				m = (message) sInput.readObject();
				
			} catch (ClassNotFoundException e) {
				System.out.println("Class not found while reading the message object");
			} catch (IOException e) {e.printStackTrace();
		}
			
			if (i == 0) {
				if(m.getData() != null){	
				decryptAESKey(m.getData());
				System.out.println();
				i++;}
				else{
					System.out.println("Error in decrypting AES key in clientThread.run()"); 
					System.exit(1);}}
			else
			{
			if(m.getData() != null){
				decryptMessage(m.getData());
				}
			}			
		  }
		}
	  }
		
		  
		  /*
			 *slanjeUKlijent klasa. 
			 * 					
			 * 		Uzima ulaznu formu sistem.in, poziva sifriranje poruke i salje je klijentu.				
			 * 
			 */ 
		
		
		
	  
	  class sendToClient extends Thread {
	        public void run(){
	        	while(true){
	        try{
	        	System.out.println("Sever: Enter OUTGOING  message : > ");
				Scanner sc = new Scanner(System.in);
				String s = sc.nextLine();
				toSend = null;
				toSend = new message(encryptMessage(s));
		//		System.out.println("new message: " + toSend);
				
			//	sOutput.writeObject(toSend);
				write();
	        }
	        	
	         catch (Exception e){	
	              e.printStackTrace();
	                System.out.println("No message sent to server");
	                break;
	                }
	        	}
	        }
	        public synchronized void write() throws IOException{
		        sOutput.writeObject(toSend);
		        sOutput.reset();
		        }
	  	}
		
	  
	  /*
	   * // ====== Primite sifrovani AES kljuc sa servera i desifrujte ga
	   * 
	   * 
	   * desifrirati AESKey metodu
	   * 				koristi privatni kljuc RSA iz privatnog javnog kljuca
	   * 					desifrujte AES kljuc sifriran pomocu javnog kljuca i poslao ga klijent.	
	   * 
	   * @param byte[] encryptedData
	   * 							Sifrovani kljuc kao bajt niz..
	   * 
	   * 
	   * 
	   */


		private void decryptAESKey(byte[] encryptedKey) {
	        SecretKey key = null; PrivateKey privKey = null; keyDecipher = null;
	        try
	        {
	            privKey = readPrivateKeyFromFile("private.key"); 			//  privatni kljuc
	            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 		// instalirati sifru...
	            keyDecipher.init(Cipher.DECRYPT_MODE, privKey );
	            key = new SecretKeySpec (keyDecipher.doFinal(encryptedKey), "AES");
	            System.out.println();
	            System.out.println(" AES key after decryption : " + key);
	            i = 1;
	            AESKey =  key;
	        }
	        catch(Exception e)
	         {  e.printStackTrace(); 
	        	System.out.println ( "exception decrypting the aes key: "  + e.getMessage() );
	             }
	       
	    }
		
		
	/*
	 * // =========== Desifrovanje  /  sifrovane poruke pomocu AES kljuca =================
	 * 
	 * decryptMessage metoda.
	 *	                 Desifruje  s ifrovanu poruku primljenu od klijenta.
	 *                   
	 *                   Uzima bajt niz sifrovane poruke kao ulaz.
	 * 
	 * 
	 */
		
		private void decryptMessage(byte[] encryptedMessage) {
	        ServerDecryptCipher = null;
	        try
	        {
	            ServerDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            ServerDecryptCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
	             byte[] msg = ServerDecryptCipher.doFinal(encryptedMessage);		            
	             System.out.println("Server: INCOMING Message From CLIENT >> " + new String(msg));
	             System.out.println("Sever: Enter OUTGOING  message : > ");
	        }
	        
	        catch(Exception e)
	         {
	        	e.getCause();
	        	e.printStackTrace();
	        	System.out.println ( "Exception genereated in decryptData method. Exception Name  :"  + e.getMessage() );
	            }
	    }
		
		/*
		 * // =========== sifrovana poruka pomocu AES kljuca =================
		 * 
		 * encryptMessage metoda
		 * 						Uzima niz poruka kao ulaz i sifruje ga.
		 * 
		 * 
		 */
		
		
		
		
		private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException, 
							InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
											BadPaddingException{
		ServerEncryptCipher = null;
    	byte[] cipherText = null;
    	ServerEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");  	
    	ServerEncryptCipher.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()) );
    	cipherText = ServerEncryptCipher.doFinal(s.getBytes());
    	
   	   return cipherText;
	}
	
		
		
		/*
		 * // ================= Cita  privatni kljuc iz datoteke =======================
		 * 
		 * readPrivateKeyFromFile metoda
		 * 	
		 * cita privatni kljuc RSA iz datoteke private.key sacuvan u istom direktorijumu.
		 *                
		 *       privatni kljuc se koristi za desifrovanje / desifrovanje AES kljuca poslatog od strane Klijenta.
		 *  
		 *  
		 *  
		 * 
		 */
		
		
		
		PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
			
			 FileInputStream in = new FileInputStream(fileName);
		  	ObjectInputStream readObj =  new ObjectInputStream(new BufferedInputStream(in));

		  	try {
		  	  BigInteger m = (BigInteger) readObj.readObject();
		  	  BigInteger d = (BigInteger) readObj.readObject();
		  	  RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
		  	  KeyFactory fact = KeyFactory.getInstance("RSA");
		  	  PrivateKey priKey = fact.generatePrivate(keySpec);
		  	  return priKey;
		  	} catch (Exception e) {
		  		  throw new RuntimeException("Some error in reading private key", e);
		  	} finally {
		 	   readObj.close();
		 	 }
			}
}

