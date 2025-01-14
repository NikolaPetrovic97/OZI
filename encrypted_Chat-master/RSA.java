/**
 * RSA.java
 * 
 * Ovaj program ce biti pozvan od strane Server programa. Ne zahteva se individualno.
 * 
 *
 * 
 * 
 */



import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;


	/*
	 *  RSA klasa
	 * 			generise RSA kljuc i cuva u lokalnim datotekama. 
	 * 
	 * 
	 * 
	 */

public class RSA {
		
		Key publicKey;
		Key privateKey;
		
		/*
		 * 
		 * glavna metoda
		 * ce napraviti objekat RSA klase i pozvati createRSA
		 * 
		 */
	
		public static void main(String[] args) throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
			
			System.out.println("Creating RSA class");
			RSA rsa = new RSA();
			rsa.createRSA();	
		}
		
		
		
		// ============ Generisanje para kljuceva =======
		
		/*
		 * createRSA metoda
		 * 					Ce kreirati dva para RSA kljuca
		 * 					Kljuvevi ce biti sacuvani kao objekt u dve odvojene datoteke.
		 */
		
		void createRSA() throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
		
			KeyPairGenerator kPairGen = KeyPairGenerator.getInstance("RSA");
			kPairGen.initialize(1024);
			KeyPair kPair = kPairGen.genKeyPair();
			publicKey = kPair.getPublic();
			System.out.println(publicKey);
			privateKey = kPair.getPrivate();
	 
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(kPair.getPublic(), RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = fact.getKeySpec(kPair.getPrivate(), RSAPrivateKeySpec.class);
			serializeToFile("public.key", pub.getModulus(), pub.getPublicExponent()); 				// ovo ce dati datoteku javnog kljuca
			serializeToFile("private.key", priv.getModulus(), priv.getPrivateExponent());			// ovo ce dati datoteku privatnog kljuca
			
		}
			
		// ===== Sacuvajte kljuceve sa specifikacijama u datoteke  ==============
		/*
		 * serializeToFile metoda
		 * 						stvarace ObjectOutput Stream i
		 * 							
		 * 						cuvati elemente kljucnih parova u lokalne datoteke.
		 * 
		 */

		void serializeToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		  	ObjectOutputStream ObjOut = new ObjectOutputStream( new BufferedOutputStream(new FileOutputStream(fileName)));

		  	try {
		  		ObjOut.writeObject(mod);
		  		ObjOut.writeObject(exp);
		  		System.out.println("Key File Created: " + fileName);
		 	 } catch (Exception e) {
		 	   throw new IOException(" Error while writing the key object", e);
		 	 } finally {
		 	   ObjOut.close();
		 	 }
			}
			
}
