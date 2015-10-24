import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.security.SecureRandom;
import java.util.BitSet;

import gnu.getopt.Getopt;


public class DES_Skeleton {
    public static boolean DEBUG = false;
    public static int K_BITS = 64;
    public static BitSet K_BITSET;
    public static BitSet[] C;
    public static BitSet[] D;
    public static BitSet[] K;
    public static int Kp_BITS = 56;
    public static BitSet Kp_BITSET;
    
	public static void main(String[] args) {
		K = new BitSet[16];
		StringBuilder inputFile = new StringBuilder();
		StringBuilder outputFile = new StringBuilder();
		StringBuilder keyStr = new StringBuilder();
		StringBuilder encrypt = new StringBuilder();
		
		pcl(args, inputFile, outputFile, keyStr, encrypt);
		
		if(keyStr.toString() != "" && encrypt.toString().equals("e")){
			encrypt(keyStr, inputFile, outputFile);
		} else if(keyStr.toString() != "" && encrypt.toString().equals("d")){
			decrypt(keyStr, inputFile, outputFile);
		}
		
		
	}
	

	private static void decrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
		try {
			PrintWriter writer = new PrintWriter(outputFile.toString(), "UTF-8");
			List<String> lines = Files.readAllLines(Paths.get(inputFile.toString()), Charset.defaultCharset());
			String IVStr = lines.get(0);
			lines.remove(0);
			String encryptedText;
			
			for (String line : lines) {
				encryptedText = DES_decrypt(IVStr, line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * TODO: You need to write the DES decryption here.
	 * @param line
	 */
	private static String DES_decrypt(String iVStr, String line) {
		
		return null;
	}


	private static void encrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
		
		try {
			PrintWriter writer = new PrintWriter(outputFile.toString(), "UTF-8");
			
			String encryptedText;
			for (String line : Files.readAllLines(Paths.get(inputFile.toString()), Charset.defaultCharset())) {
				encryptedText = DES_encrypt(line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		
	}
	/**
	 * TODO: You need to write the DES encryption here.
	 * @param line
	 */
	private static String DES_encrypt(String line) {
		
        
		return null;
	}


    static void genDESkey(){
        SecureRandom rnd = new SecureRandom();
        K_BITSET = new BitSet();
        for(int i = 0; i < K_BITS; i++) {
            K_BITSET.set(i, rnd.nextBoolean());
        }
        if (DEBUG) {
            System.out.println("K: ");
            printAsBinary(K_BITSET, 0);
            System.out.println();
        }
    }
    
    static void permute56bits() {
        Kp_BITSET = new BitSet(Kp_BITS);
        for (int i = 0; i < Kp_BITS; i++) {
            Kp_BITSET.set(i, K_BITSET.get(SBoxes.PC1[i]));
        }
        if (DEBUG) {
            System.out.println("K+: ");
            printAsBinary(Kp_BITSET, 0);
            System.out.println();
        }
    }
    
    static void genKeys() {
        C = new BitSet[17];
        D = new BitSet[17];
        BitSet left = new BitSet();
        BitSet right = new BitSet();
        // set left & right bits
        for (int i = 0; i < 28; i++) {
            left.set(i, Kp_BITSET.get(i));
        }
        int index = 28;
        for (int k = 0; k < 28; k++) {
            right.set(k, Kp_BITSET.get(index+k));
        }
        BitSet c = left;
        C[0] = c;
        BitSet d = right;
        D[0] = d;
        for (int i = 0; i < 16; i++) {
            c = shiftLeft(c,SBoxes.rotations[i]);
            C[i+1] = c;
            d = shiftLeft(d,SBoxes.rotations[i]);
            D[i+1] = d;
        }
        
        if (DEBUG) {
            System.out.println();
            for (int i = 0; i < 17; i++) {
                System.out.print("C-"+(i)+": ");
                printAsBinary(C[i], 28);
                System.out.print("D-"+(i)+": ");
                printAsBinary(D[i], 28);
            }
        }
        KKeys();
    }
    
    public static void KKeys() {
        BitSet gen = new BitSet();
        BitSet[] genArr = new BitSet[17];
        
        int fetchIndex = 0;
        for (int j = 1; j < 17; j++) {
            gen = C[j];
            for(int i= 28; i < 56; i++) {
                gen.set(i, D[j].get(fetchIndex));
                fetchIndex++;
            }
            genArr[j-1] = gen;
            fetchIndex = 0;
        }
        
        if (DEBUG) {
            System.out.println();
            for (int i = 0; i < 16; i++) {
                printAsBinary(genArr[i], 56);
            }
            System.out.println();
        }
        
        for (int i = 0; i < 16; i++) {
            BitSet gen2 = new BitSet();
            for (int j = 0; j < 48; j++) {
                gen2.set(j, genArr[i].get(SBoxes.PC2[j]));
            }
            K[i] = gen2;
        }
        
        if (DEBUG) {
            System.out.println();
            for (BitSet entry : K) {
                printAsBinary(entry, 48);
            }
        }
    }
    
    public static BitSet shiftLeft(BitSet left, int numShift) {
        BitSet c = new BitSet(28);
        c = left;
        boolean o;
        for (int i = 0; i < numShift; i++) {
            o = c.get(0);
            c = c.get(1, c.length());
            c.set(27,o);
            assert(o == c.get(c.length()));
        }
        return c;
    }
    
    static void printAsBinary(BitSet bs, int size) {
        if (size == 0) {
            size = bs.size();
        }
        
        for (int i = 0; i < size; i++) {
            if (bs.get(i)) { // if true, 1 
                System.out.print(1);
            } else { // else is 0
                System.out.print(0);
            }
        }
        System.out.println();
    }
    
	/**
	 * This function Processes the Command Line Arguments.
	 * -p for the port number you are using
	 * -h for the host name of system
	 */
	private static void pcl(String[] args, StringBuilder inputFile,
							StringBuilder outputFile, StringBuilder keyString,
							StringBuilder encrypt) {
		/*
		 * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
		*/	
		Getopt g = new Getopt("Chat Program", args, "hke:d:i:o:");
		int c;
		String arg;
		while ((c = g.getopt()) != -1){
		     switch(c){
		     	  case 'o':
		        	  arg = g.getOptarg();
		        	  outputFile.append(arg);
		        	  break;
		     	  case 'i':
		        	  arg = g.getOptarg();
		        	  inputFile.append(arg);
		        	  break;
	     	  	  case 'e':
		        	  arg = g.getOptarg();
		        	  keyString.append(arg);
		        	  encrypt.append("e");
		        	  break;
	     	  	  case 'd':
		        	  arg = g.getOptarg();
		        	  keyString.append(arg);
		        	  encrypt.append("d");
		        	  break;
		          case 'k':
		        	  genDESkey();
		        	  break;
		          case 'h':
		        	  callUseage(0);
		          case '?':
		            break; // getopt() already printed an error
		            //
		          default:
		              break;
		       }
		   }
		
	}
	
	private static void callUseage(int exitStatus) {
		
		String useage = "";
		
		System.err.println(useage);
		System.exit(exitStatus);
		
	}
	
}
