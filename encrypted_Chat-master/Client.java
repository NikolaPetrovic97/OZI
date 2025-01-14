
/**
 * Client.java
 *  
 *  Zavisnost : Sever.java, message.java, RSA.java
 *  
 * Pokreni Klijent samo nakon pokretanja Server programa.
 *  
 *
 *  Reference:
 *  http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html
 *  http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
 * 
 */


import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

//import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/*
 * 
 * Klijent javne klase.
 * 
 *  Klijent ce poslati sšifrovanu poruku serveru.
 *  
 *  Prva poruka poslata na server je kljuc AES. Klijent ce poslati sifrovanu poruku serveru. 
 *  
 *	Nakon toga klijent ce traziti unos. Obezbedjeni unos ce biti sifrovan pomocu AES kljuca i bice poslat na server.  
 * 
 */

public class Client {

	private ObjectOutputStream sOutput;
	private ObjectInputStream sInput;

	private Socket socket;
	private String server;
	private int port;
	private Cipher cipher1;
	private Cipher cipher2;
	int i = 0;
	message m;
	SecretKey AESkey;
	message toSend;
	static String IV = "AAAAAAAAAAAAAAAA";
	
	
	
	// ===== Konstrukcija  ==========
	
	Client (String server, int port){ 						
	this.server = server;
	this.port = port;
	}
	
	
	
	/*
	 * 
	 * Glavni metod
	 * 
	 * Kreira instancu klijentske klase sa obezbedjenom adresom servera i TCP portom za uspostavljanje konekcije soketa.
	 * 
	 *  
	 * 			Argumenti komandne linije.
	 * 
	 * Protok programa:	
	 * 
	 * 		MAIN --> start() & getKey()
	 * 		start() ---> sendToServer Thread
	 * 		sendToServer Thread ---> EncryptSecretKey() or encryptData(string)
	 * 
	 * 
	 */
	
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		
		String serverAddress;
	
		int portNumber = 8002;
		if(args.length < 1){
		System.out.println("#############################################################");
		System.out.println("# 															 ");
		System.out.println("# Usage: $ java Client [sever ip]							 ");
		System.out.println("# 															 ");
		System.out.println("# e.g. $ java Client 192.168.1.1																 ");
		System.out.println("# 							 								 ");
		System.out.println("# NO ARGUMENT REQUIRED IF SERVER RUNNING ON LOCALHOST		 ");
		System.out.println("# 															 ");
		System.out.println("#############################################################");
		
		serverAddress = "localhost";
		}
		else{
			serverAddress = args[0];
		}
		Client client = new Client(serverAddress, portNumber);
		client.generateAESkey();
		client.start();
	}
	
	/*
	 * pocetna metoda.
	 * 				uspostavlja socket konekciju sa serverom.
	 * 
	 * 
	 */
	
	void start() throws IOException{
		socket = new Socket(server, port);
		System.out.println("connection accepted " + socket.getInetAddress() + " :"  + socket.getPort());
		
		
		sInput = new ObjectInputStream(socket.getInputStream());
		sOutput = new ObjectOutputStream(socket.getOutputStream());
		
		new sendToServer().start();
		new listenFromServer().start();
	}
	
	
	
	/*
	 * 
	 *  listenFromServer metoda.
	 *  						Prima poruku sa servera i poziva metod desifrovanja.
	 * 
	 * 
	 */
	
	

	class listenFromServer extends Thread {
		public void run(){
			while(true){
        try{
     m = (message) sInput.readObject();
       decryptMessage(m.getData());
      } catch (Exception e){
       		e.printStackTrace();
              System.out.println("connection closed");
                }
      	}
	}
	}

	
	
	/*
	 * sendToServer klasa. Prosiruje klasu niti. Radi kontinuirano.
	 * 
	 * 						Salje sifrovane poruke na server.
	 * 						Prva poruka poslata serveru ce biti sifrovana AES kljucem. Isti kljuc ce koristiti server za desifrovanje buducih poruka.
	 * 
	 * 						Kada se kljuc AES deli, klijent ce prihvatiti ulazne signale i sifrovati ga pre slanja na server.
	 * 
	 * 
	 */
	
	
	class sendToServer extends Thread {
        public void run(){
        	while(true){
        try{
	
        if (i == 0){	
        	toSend = null;
   
    	toSend = new message(encryptAESKey());
		sOutput.writeObject(toSend);
        	i =1;
        	}					
        
        else{
        	
        	System.out.println("CLIENT: Enter OUTGOING message > ");
			Scanner sc = new Scanner(System.in);
			String s = sc.nextLine();
			toSend = new message(encryptMessage(s));
			sOutput.writeObject(toSend);
        	}
        	
        } catch (Exception e){
              e.printStackTrace();
                System.out.println("No message sent to server");
                break;
                }
        	}
        }
	}

	
	/*
	 * //============== Pravljenje AES kljuca =================================
	 * 
	 * generateAESkey metoda
	 * 
	 * 						Pozvan glavnom metodom, generise se AES kljuc za sifriranje / desifrovanje poruka razmijenjenih izmedju klijenta i servera.
	 */
	
	void generateAESkey() throws NoSuchAlgorithmException{
	AESkey = null;
	KeyGenerator Gen = KeyGenerator.getInstance("AES");
	Gen.init(128);
	AESkey = Gen.generateKey();
	System.out.println("Genereated the AES key : " + AESkey);
	}
	
	
	
	/*
	 * // ====== Citanje  RSA javnog kljuca za sifrovanje AES kljuca  ==================
	 * 
	 * encryptAESKey metoda.
	 * 
	 * Da sifruje AES kljuc koji generise metod generateAESkey. Takodje ce izracunati vreme potrebno za sifrovanje AES kljuca pomocu RSA metode sifrovanja.
	 * 
	 * Za sifrovanje AES kljuca, ovaj metod ce procitati javni kljuc RSA iz RSA javnih = privatnih kljuceva koji su sacuvani u istom direktorijumu.	  							
	 * 
	 * Zavisnost: datoteka javnog kljuca "public.key" bi trebalo da bude sacuvana u istom direktorijumu. 
	 * 	
	 */
		

	private byte[] encryptAESKey (){
		cipher1 = null;
    	byte[] key = null;
  	  try
  	  {
		 PublicKey pK = readPublicKeyFromFile("public.key");
	 	  System.out.println("Encrypting the AES key using RSA Public Key" + pK);
   	     // Inicijalizirajte sifru pomocu javnog kljuca korisnika
   	     cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
   	    
   	     cipher1.init(Cipher.ENCRYPT_MODE, pK );
   	     long time1 = System.nanoTime();
   	     key = cipher1.doFinal(AESkey.getEncoded());   // ovaj sifrovani kljuce biti poslat na server.
   	     long time2 = System.nanoTime();
   	     long totalRSA = time2 - time1;
   	     System.out.println("Time taken by RSA Encryption (Nano Seconds) : " + totalRSA);
   	     i = 1;
   	 	}
  	  
   	 catch(Exception e ) {
    	    System.out.println ( "exception encoding key: " + e.getMessage() );
    	    e.printStackTrace();
   	 		}
  	  return key;
  	  } 
	
	
		/*
		 * //============= Sifriraj podatke za slanje =================
		 * 
		 * encryptMessage metoda
		 * 	Sifruje ulazni niz koristeci AES sifrovanje pomocu AES kljuca generisanog generisanjem AESkey metode.
		 * 
		 *  niz s
		 * 					Ulazni niz za sifrovanje
		 * 
		 * Vraca bajt niz kao rezultat.
		 * 
		 */

	
		private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException, 
							InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
											BadPaddingException{
		cipher2 = null;
    	byte[] cipherText = null;
    	cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	
    	cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()) );
    	long time3 = System.nanoTime();
    	cipherText = cipher2.doFinal(s.getBytes());
    	long time4 = System.nanoTime();
		long totalAES = time4 - time3;
		System.out.println("Time taken by AES Encryption (Nano Seconds) " + totalAES);
   	   return cipherText;
	}
	
		
	/*
	 * //=========== Desfiruje primljenu poruku pomocu AES kljuca =================
	 * 
	 * decryptMessage metoda, ce desiforavati sifrovani tekst primljen sa servera. Trenutno onemogucen, moze se omoguciti za dvosmernu komunikaciju.
	 * 
	 *  byte[] data
	 * 					uzima bajt niz sifrovane poruke kao ulaz. Vraca obican tekst.
	 * 
	 * 	
	 */
	
		
		private void decryptMessage(byte[] encryptedMessage) {
	        cipher2 = null;
	        try
	        {
	            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            cipher2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
	             byte[] msg = cipher2.doFinal(encryptedMessage);		            
	             System.out.println("CLIENT: INCOMING Message From Server   >> " + new String(msg));
	             System.out.println("CLIENT: Enter OUTGOING message > ");
	        }
	        
	        catch(Exception e)
	         {
	        	e.getCause();
	        	e.printStackTrace();
	        	System.out.println ( "Exception genereated in decryptData method. Exception Name  :"  + e.getMessage() );
	            }
	    }
	
		
		
	/*
	 * closeSocket metoda  	//============== Da zatvorite sve ulaze  i tokove.===================
	 * 						Zatvara ulazne / izlazne tokove i ulaze 
	 * 
	 * 
	 */
		

	public void closeSocket() {
		try{
	if(sInput !=null) sInput.close();
	if(sOutput !=null) sOutput.close();
	if(socket !=null) socket.close();
		}catch (IOException ioe){
			System.out.println("Error in Disconnect methd");
			}
		}
	
	
		/*
		 *  // ===================== Citanje javnog kljuca RSA iz datoteke ===============
		 * 
		 * readPublicKeyFromFile metoda.
		 * 
		 * 								Citace javni kljuc RSA iz datoteke "public.key" 
		 * 								na istom direktorijumu za sifrovanje AES kljuca.
		 * 
		 */
	
	
	
		PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		
	 	FileInputStream in = new FileInputStream(fileName);
	  	ObjectInputStream oin =  new ObjectInputStream(new BufferedInputStream(in));

	  	try {
	  	  BigInteger m = (BigInteger) oin.readObject();
	  	  BigInteger e = (BigInteger) oin.readObject();
	  	  RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e);
	  	  
	  	  KeyFactory kF = KeyFactory.getInstance("RSA");
	  	  PublicKey pubK = kF.generatePublic(keySpecifications);
	  	  return pubK;
	  	} catch (Exception e) {
	  		  throw new RuntimeException("Some error in reading public key", e);
	  	} finally {
	 	   oin.close();
	 	 }
		}
}



