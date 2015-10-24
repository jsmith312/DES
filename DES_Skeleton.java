import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import gnu.getopt.Getopt;


public class DES_Skeleton {
    private int K_BITS = 64;
    private BitSet K_BITSET;
    private int Kp_BITS = 56;
    private BitSet Kp_BITSET;
    private int R = 56;
    
	public static void main(String[] args) {
		
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
        K_BITSET = new BitSet(64);
        for(int i = 0; i < K_BITS; i++) {
            K_BITSET.set(i, rnd.nextBoolean());
        }
        System.out.println("K: ");
        System.out.println(K_BITSET.length());
        printAsBinary(K_BITSET);
    }
    
    static void permute56bits() {
        Kp_BITSET = new BitSet(56);
        for (int i = 0; i < SBoxes.PC1.length; i++) {
            Kp_BITSET.set(i, K_BITSET.get(SBoxes.PC1[i]));
        }
        System.out.println("K+: ");
        System.out.println(Kp_BITSET.length());
        printAsBinary(Kp_BITSET);
    }
    
    static void genKeys() {
        BitSet left = new BitSet(28);
        BitSet right = new BitSet(28);
        int rightSide = 0;
        
        // set left & right bits
        for (int i = 0; i < 28; i++) {
            left.set(i, Kp_BITSET.get(i));
        }
        int index = 28;
        for (int k = 0; k < 28; k++) {
            right.set(k, Kp_BITSET.get(index+k));
        }
        
        System.out.print("C-0: ");
        printAsBinary(left);
        System.out.println();
        System.out.println(left.length());
        System.out.print("D-0: \n");
        System.out.println(right.length());
        printAsBinary(right);
    }
    
    static void printAsBinary(BitSet bs) {
        for (int i = 0; i < bs.length(); i++) {
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
