/**
 * message.java 
 * 
 * 
 *
 * 
 */



import java.io.Serializable;


/*
 * poruka javne klase
 * 
 * 					Kreira serijski objekt sa sadrzajem poruke
 * 					za razmenu izmedju klijenta i servera.
 */


public class message implements Serializable{
		
		private static final long serialVersionUID = 1L;
			byte[] data; 
			
			message(byte[] data){
				this.data = data;
			}
			
			/*
			 *getData motoda
			 *				vraca niz bajtova.
			 */
			
			byte[] getData(){
				return data;
			}
			
		}	
