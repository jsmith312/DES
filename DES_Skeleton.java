import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.security.SecureRandom;
import java.util.BitSet;

import java.util.BitSet;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64.Encoder;

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
	public static String hex;
    public static BitSet IV;

	public static void main(String[] args) {
		K = new BitSet[16];
		StringBuilder inputFile = new StringBuilder();
		StringBuilder outputFile = new StringBuilder();
		StringBuilder keyStr = new StringBuilder();
		StringBuilder encrypt = new StringBuilder();

		pcl(args, inputFile, outputFile, keyStr, encrypt);

		if (keyStr.toString() != "" && encrypt.toString().equals("e")) {
			K_BITSET = hexToBinary(keyStr.toString(), 64);
			encrypt(keyStr, inputFile, outputFile);
		} else if (keyStr.toString() != "" && encrypt.toString().equals("d")) {
            K_BITSET = hexToBinary(keyStr.toString(), 64);
			decrypt(keyStr, inputFile, outputFile);
		}
	}

	private static void decrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
        PrintWriter writer = null;
		try {
			writer = new PrintWriter(outputFile.toString(), "UTF-8");
			List<String> lines = Files.readAllLines(
					Paths.get(inputFile.toString()), Charset.defaultCharset());
            IV = hexToBinary(lines.get(0), 64);
			lines.remove(0);
			String encryptedText;
            String IVStr = "";
			for (String line : lines) {
				encryptedText = DES_decrypt(IVStr, line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
        } finally {
            writer.print("\n");
            writer.flush();
            writer.close();
        }

	}

	/**
	 * TODO: You need to write the DES decryption here.
	 * 
	 * @param line
	 */
	private static String DES_decrypt(String iVStr, String line) {
        //printAsBinary(K_BITSET, 64);
        permute56bits();
        //printAsBinary(Kp_BITSET, 56);
        genKeys();
        KKeys();
        //for(int i = 0; i < 16; i++) {
        //printAsBinary(K[i], 48);
        //}
        //prepare message
        BitSet M;
        String result="";
        //byte[] bytes = line.getBytes();
        for (int i = 0; i < line.length(); i+=64) {
            M = hexToBinary(line, 64);
            result += messageDecrypt(M);
        }
        return result;
	}

	private static void encrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
        PrintWriter writer = null;
		try {
			writer = new PrintWriter(outputFile.toString(), "UTF-8");

			String encryptedText;
            genIV();
            writer.print(hexConv(IV, K_BITS)+"\n");
			for (String line : Files.readAllLines(
					Paths.get(inputFile.toString()), Charset.defaultCharset())) {
				encryptedText = DES_encrypt(line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
        } finally {
            if (writer != null) {
                    writer.flush();
                    writer.close();
            }
            
        }
    }

	/**
	 * TODO: You need to write the DES encryption here.
	 * 
	 * @param line
	 */
	private static String DES_encrypt(String line) {
        //printAsBinary(K_BITSET, 64);
		permute56bits();
        //printAsBinary(Kp_BITSET, 56);
		genKeys();
		KKeys();
        //for(int i = 0; i < 16; i++){
        //printAsBinary(K[i], 48);
        //}
        //prepare message
		BitSet M;
		byte[] bytes = line.getBytes();
		// leading zeros
		String[] array = { "", "0", "00", "000" };
		String str = "", bits = "", result="";
		int diff = 0;
		// convert line to bit string
		for (int i = 0; i < line.length(); i++) {
			str = Integer.toBinaryString(bytes[i]);
			if (str.length() > 4) {
				diff = (8 - str.length());
			}
			bits += (array[diff] + str);
		}
		//If last M in line has less than 64bits append 0's
		int size = bits.length(), j = (64 - (size % 64)), k = 0;
		for(int i = 0; i < j; i++){
			bits += "0";
		}
        //System.out.println("Bit Length: "+size);
		size = (bits.length()/64);
		//encrypt each message-block of line
		for(int i = 0; i < size; i++){
			M = new BitSet();
			//set bits in new BitSet
			for(int n = 0; n < 64; n++){
				if(bits.charAt(k) == '1'){
					M.set(n, true);
				}else{
					M.set(n, false);
				}
				k++;
			}
            M.xor(IV);
            //encrypt message
			result+= messageEncrypt(M)+"\n";
		}
		return result;
	}
	
	/**
	 * messageEncrypt():
	 */
	public static String messageEncrypt(BitSet M){
		BitSet IP = encryptIP(M);
		BitSet L =new BitSet(), R = new BitSet(), temp = new BitSet(), F = new BitSet();
		for(int i = 0; i<32; i++){
			L.set(i, IP.get(i));
		}
		for(int i = 0; i<32;i++){
			R.set(i, IP.get(i+32));
		}
		//Generate R and L for 16 rounds
		for(int i = 0; i < 16; i++){
			for(int j = 0; j < 32; j++){
				temp.set(j, R.get(j));
			}
			F = calculateF(R, i);
			L.xor(F);
			for(int j = 0; j < 32; j++){
				R.set(j, L.get(j));
			}
			for(int j = 0; j < 32; j++){
				L.set(j, temp.get(j));
			}
		}

		BitSet RL = new BitSet(), newSet = new BitSet();
		for(int i = 0; i < 32; i++){
			RL.set(i, R.get(i));
			RL.set(i+32, L.get(i));
		}	
		//permute newSet with SBoxes.FP
		for(int i = 0; i < 64; i++){
			newSet.set(i, RL.get(SBoxes.FP[i] - 1));
		}
        //set IV to new encrypted block
        for(int i = 0; i< K_BITS; i++){
            IV.set(i, newSet.get(i));
        }
		return hexConv(newSet, 64);
	}
    
    /**
     * messageDecrypt():
     */
    public static String messageDecrypt(BitSet M) {
        BitSet IP = encryptIP(M);
        int iter = 15;
        BitSet L =new BitSet(), R = new BitSet(), temp = new BitSet(), F = new BitSet();
        for(int i = 0; i<32; i++){
            L.set(i, IP.get(i));
        }
        for(int i = 0; i<32;i++){
            R.set(i, IP.get(i+32));
        }
        
        //Generate R and L for 16 rounds
        for(int i = 0; i < 16; i++){
            for(int j = 0; j < 32; j++){
                temp.set(j, R.get(j));
            }
            F = calculateF(R, iter);
            iter--;
            L.xor(F);
            for(int j = 0; j < 32; j++) {
                R.set(j, L.get(j));
            }
            for(int j = 0; j < 32; j++) {
                L.set(j, temp.get(j));
            }
        }
        
        BitSet RL = new BitSet(), newSet = new BitSet();
        for(int i = 0; i < 32; i++){
            RL.set(i, R.get(i));
            RL.set(i+32, L.get(i));
        }
        
        //permute newSet with SBoxes.FP
        for(int i = 0; i < 64; i++){
            newSet.set(i, RL.get(SBoxes.FP[i] - 1));
        }
        newSet.xor(IV);
        // update Iv to be previous ciphertext
        for(int i = 0; i< K_BITS; i++) {
            IV.set(i, M.get(i));
        }
        String ret = BitSetToString(newSet, 0);
        String ret2 = binaryToASCII(ret);
        return ret2;
    }
    
	/**
	 * IP():
	 * 
	 */
	public static BitSet encryptIP(BitSet M){
		BitSet IPSet = new BitSet();
		for(int i = 0; i < 64; i++){
			IPSet.set(i, M.get(SBoxes.IP[i] - 1)); 
		}
		return IPSet;
	}
	
	/**
	 * calculateFD():
	 * 
	 * Input 32 bit R BitSet and retrieve new 48 bit BitSet through use of E, S and P tables.
	 */
	public static BitSet calculateF(BitSet R, int val){
		BitSet key = new BitSet(), E = new BitSet(), S = new BitSet(), P = new BitSet(), B, var = new BitSet();
		for(int i = 0; i < 48; i++){
			key.set(i, K[val].get(i));
		}
        //key = K[val].get(0, 48);
		//expand R with SBoxes.E
		for(int i = 0; i < 48; i++){
			E.set(i, R.get(SBoxes.E[i] - 1));
		}
		E.xor(key);
		//calculate S with SBoxes.S
		//call calculateS() for each box B and set S accordingly
		
		for(int i = 0; i < 48; i+=6){	
			int c = i;
			for(int k = 0; k < 6; k++){
				var.set(k, E.get(c));
				c++;
			}
			B = calculateS(var, i/6);
			
			for(int j = 0; j < 4; j++){
				S.set((j + (4*(i/6))), B.get(j));
			}
		}
		//permutate S with SBoxes.P
		for(int i = 0; i < 32; i++){
			P.set(i, S.get(SBoxes.P[i] - 1));
		}
		return P;
	}
	
	/**
	 * calculateS():
	 * 
	 * Use SBoxes.S to permute 6bit blocks into 4bit blocks 
	 */
	public static BitSet calculateS(BitSet B, int boxNum){
		String iStr="", jStr="", dec = "", bits = "";
		String[] array = { "", "0", "00", "000" };
		int i = 0, j = 0, d = 0, diff = 0;
		boolean bool;
		//calculate j (column)
		for(int n = 1; n < 5; n++){
			bool = B.get(n);
			if(bool == true){
				jStr += "1";
			}else{
				jStr += "0";
			}
		}
		//calculate i (row)
		if(B.get(0) == true){
			iStr += "1";
		}else{
			iStr += "0";
		}
		if(B.get(5) == true){
			iStr += "1";
		}else{
			iStr += "0";
		}
		i = Integer.parseInt(iStr, 2);
		j = Integer.parseInt(jStr, 2);	
		//use SBoxes.S to permutate B. Requires i(row), j(column) and d (S[#][d])
		d = ((16 * i) + j);
				
		int sVal = SBoxes.S[boxNum][d];
		dec = Integer.toString(sVal, 2);
	
		//formalize
		if (dec.length() < 4) {
			diff = (4 - dec.length());
			bits = (array[diff] + dec);	
		}else{
			bits = dec;
		}
		
		BitSet SB = new BitSet();
		for(int n = 0; n < 4; n++){
			if(bits.charAt(n) == '1'){
				SB.set(n, true);
			}else{
				SB.set(n, false);
			}
		}
		return SB;
	}
    
    public static void genIV(){
        SecureRandom rnd = new SecureRandom();
        IV = new BitSet();
        for (int i = 0; i < K_BITS; i++) {
            IV.set(i, rnd.nextBoolean());
        }
    }

	/**
	 * genDESkey:
	 * 
	 * Generates key and 16 sub keys. Checks for weak key based on sub key
	 * comparisons.
	 */
	static void genDESkey() {
		for (;;) {
			SecureRandom rnd = new SecureRandom();
			K_BITSET = new BitSet();
			for (int i = 0; i < K_BITS; i++) {
				K_BITSET.set(i, rnd.nextBoolean());
			}
			hex = hexConv(K_BITSET, K_BITS);
			// run key breakdown
			permute56bits();
			genKeys();
			KKeys();
			// check for weak key
			if (keyCheck()) {
				System.out.println(hex);
				break;
			}
			if (DEBUG) {
				System.out.println("K: ");
				printAsBinary(K_BITSET, 0);
				System.out.println();
			}
		}
	}

	static void permute56bits() {
		Kp_BITSET = new BitSet(Kp_BITS);
		for (int i = 0; i < Kp_BITS; i++) {
			Kp_BITSET.set(i, K_BITSET.get(SBoxes.PC1[i] - 1));
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
			right.set(k, Kp_BITSET.get(index + k));
		}
		BitSet c = left;
		C[0] = c;
		BitSet d = right;
		D[0] = d;
		for (int i = 0; i < 16; i++) {
			c = shiftLeft(c, SBoxes.rotations[i]);
			C[i + 1] = c;
			d = shiftLeft(d, SBoxes.rotations[i]);
			D[i + 1] = d;
		}

		if (DEBUG) {
			System.out.println();
			for (int i = 0; i < 17; i++) {
				System.out.print("C-" + (i) + ": ");
				printAsBinary(C[i], 28);
				System.out.print("D-" + (i) + ": ");
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
			for (int i = 28; i < 56; i++) {
				gen.set(i, D[j].get(fetchIndex));
				fetchIndex++;
			}
			genArr[j - 1] = gen;
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
				gen2.set(j, genArr[i].get(SBoxes.PC2[j] - 1));
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

	/**
	 * keyCheck():
	 * 
	 * If any sub keys are equal then the original key is weak key. Signals that
	 * key contains patterns or all of one value.
	 */
	public static boolean keyCheck() {
		for (int i = 0; i < 15; i++) {
			for (int j = 0; j < 16; j++) {
				BitSet temp = K[i].get(0, 64);
				temp.xor(K[j]);
				if (i != j && temp.isEmpty()) {
					return false;
				}
			}
		}
		return true;
	}

	public static BitSet shiftLeft(BitSet left, int numShift) {
		BitSet c = new BitSet(28);
		c = left;
		boolean o;
		for (int i = 0; i < numShift; i++) {
			o = c.get(0);
			c = c.get(1, c.length());
			c.set(27, o);
			assert (o == c.get(c.length()));
		}
		return c;
	}

	/**
	 * hexConv():
	 * 
	 * Converts BitSet to hexadecimal string
	 */
	public static String hexConv(BitSet set, int size) {
		String hex = "", s = "", full = "";
		for (int i = 0; i < size; i++) {
			if (set.get(i) == true) {
				hex += "1";
			} else {
				hex += "0";
			}
		}
		int j = 0;
		for (int i = 0; i < 16; i++) {
			s = hex.substring(j, j + 4);
			j += 4;
			full += Integer.toHexString(Integer.parseInt(s, 2));
		}
		return full;
	}

    static String binaryToASCII(String s) {
        String s2 = "";
        char nextChar;
        for(int i = 0; i <= s.length()-8; i += 8) //this is a little tricky.  we want [0, 7], [9, 16], etc
        {
            nextChar = (char)Integer.parseInt(s.substring(i, i+8), 2);
            s2 += nextChar;
        }
        return s2;
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
    
    static String BitSetToString(BitSet bs, int size) {
        StringBuffer buff = new StringBuffer();
        if (size == 0) {
            size = bs.size();
        }
        for (int i = 0; i < size; i++) {
            if (bs.get(i)) { // if true, 1
                buff.append("1");
            } else { // else is 0
                buff.append("0");
            }
        }
        return buff.toString();
    }
	
	public static BitSet hexToBinary(String hex, int size){
		BitSet set = new BitSet();
		BigInteger h = new BigInteger(hex, 16);
		String b = h.toString(2);
		if(b.length() < 64){
			int diff = 64 - b.length();
			for(int i = 0; i < diff; i++){
				b = "0"+b;
			}
		}
		for(int i = 0; i < b.length(); i++){
			if(b.charAt(i) == '1'){
				set.set(i, true);
			}else{
				set.set(i, false);
			}
		}
		
		return set;
	}

	/**
	 * This function Processes the Command Line Arguments. -p for the port
	 * number you are using -h for the host name of system
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
		while ((c = g.getopt()) != -1) {
			switch (c) {
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
