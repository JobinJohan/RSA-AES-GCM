package tunnelrsa;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Create a pair of public private key using the RSA algorithm
 * @author Johan Jobin, University Of Fribourg, 2018
 */
public class Rsa {
    
    private final BigInteger privateKey; // (d, n)
    private final BigInteger publicKey; // (e,n)
    private BigInteger n;

    public Rsa(int numberOfBits){
        BigInteger one  = new BigInteger("1");
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(numberOfBits/2, random);
        BigInteger q = BigInteger.probablePrime(numberOfBits/2, random);
        BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));
       
        n = p.multiply(q);
        BigInteger e;
        do{
            e = new BigInteger(phi.bitLength(), random);
        }while(e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
       
        publicKey = e;
        BigInteger d = publicKey.modInverse(phi);
        privateKey = d;    
    }
   
    public Rsa(BigInteger publicKey, BigInteger n){
        this.publicKey=publicKey;
        this.privateKey=null;
        this.n = n;
    }
   
 
   
    BigInteger encrypt(BigInteger message){
        return message.modPow(publicKey, n );
    }

    BigInteger decrypt(BigInteger encrypted) throws Exception{
        if(privateKey!=null){
            return encrypted.modPow(privateKey, n);
        }
        else{
            throw new Exception();
        }
      
    }
   
    public String toString(){
        String s = "";
        s += "public  = " + publicKey  + "\n";
        s += "private = " + privateKey + "\n";
        s += "p*q = " + n;
        return s;
    }
   
    public BigInteger getPrivateKey(){
        return privateKey;
    }
   
    public BigInteger getPublicKey(){
        return publicKey;
    }
   
    public BigInteger getN(){
        return n;
    }
        
    
}
