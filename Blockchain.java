/*--------------------------------------------------------

Chadwick




4. Precise examples / instructions to run this program:

(instructions for mac)

> java -cp ".:gson-2.8.2.jar" Blockchain 0
> java -cp ".:gson-2.8.2.jar" Blockchain 1
> java -cp ".:gson-2.8.2.jar" Blockchain 2





In this current implementation, I have the work loop set to continue running as if we are waiting for more input. 

The reverification of the blockchain is implemented alongside allowing user input. The input will be prompted for 
towards the end of the verification process. 
I implemented the additional L, V, C and R commands as well, but the prompt will show up towards the end of verification. 




----------------------------------------------------------*/
//importing important java utilities for In/Out, sockets, etc.
import java.io.*;
import java.net.*;
import java.util.*;

//Getting all the Java Security Libraries necessary. 
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.spec.*;
import java.security.*;

//Getting some libraries for the queues, dates, and a few other specific things. 
import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.text.*;
import java.util.Base64;
import java.util.Arrays;
import java.lang.reflect.*;

//Getting libraries for GSON
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.*;
//Some specific libraries from IO, probably not necessary as I imported io.*
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;

/*
Explanation of this implementation: This implemenation follows the procedure of sending a single updated block to other processes rather 
than sending the entire blockChain each time. The starting process is process 2 which sends a start signal to each of the other processes. 
When each process receives the start signal, it continue through executing particular methods such as reading keys, reading the text files and
finally starting the process of verifying the blocks. Each process maintains its own copy of the ledger that it only access when the block is 
received and verified. If a block receives an update block, as long as it doesn't exist in the blockchain, it will always add the block. 
Process 0 has the job of creating the dummy block and sending that to each of the processes so that they all start with the same initial block.
I wanted this to be more realistic than just automatically adding the block to the chain for each process, so I used the same process as I would 
for another verified block and sent it to the process. This way we have a true SHA256 hash digest of the block as well. 

Credit to particular sources:
Thanks: http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example
https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
*/

class BlockRecord{
	
	/*
	This is our class of getters and setters that will allow us to store all the data for the block. 
	*/
  String BlockID;//Our unique BlockID created at time of read-in
  String SignedBlockID;
  String BlockNum;
  String CreatorHash;
  String CreatorSignedHash;
  String CreationProcess;
  String TimeStamp;//This is our timestamp, may considering changing type 
  String SignedWinningHash;
  String VerificationProcessID;//This will store the process ID that verifies the block for credit
  String PreviousHash; //This will store winning hash of previous block. 
  String WinningHash;
  String RandomSeed; 
  UUID uuid; 
  String Fname;
  String Lname;
  String SSNum;
  String DOB;
  String Diag;
  String Treat;
  String Rx;
  
  

  
  



  
  public String getBlockID() {return BlockID;}
  public void setBlockID(String BID){this.BlockID = BID;}

  public String getSignedWinningHash() {return SignedWinningHash;}
  public void setSignedWinningHash (String SWH){this.SignedWinningHash = SWH;} 

  public String getSignedBlockID() {return SignedBlockID;}
  public void setSignedBlockID(String SBI){this.SignedBlockID = SBI;}

  public String getTimeStamp() {return TimeStamp;}
  public void setTimeStamp(String TS){this.TimeStamp = TS;}

  public String getVerificationProcessID() {return VerificationProcessID;}
  public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
  
  public String getPreviousHash() {return this.PreviousHash;}
  public void setPreviousHash (String PH){this.PreviousHash = PH;}
  
  public UUID getUUID() {return uuid;} 
  public void setUUID (UUID ud){this.uuid = ud;}

  public String getLname() {return Lname;}
  public void setLname (String LN){this.Lname = LN;}
  
  public String getFname() {return Fname;}
  public void setFname (String FN){this.Fname = FN;}
  
  public String getSSNum() {return SSNum;}
  public void setSSNum (String SS){this.SSNum = SS;}
  
  public String getDOB() {return DOB;}
  public void setDOB (String RS){this.DOB = RS;}

  public String getDiag() {return Diag;}
  public void setDiag (String D){this.Diag = D;}

  public String getTreat() {return Treat;}
  public void setTreat (String Tr){this.Treat = Tr;}

  public String getRx() {return Rx;}
  public void setRx (String Rx){this.Rx = Rx;}

  public String getRandomSeed() {return RandomSeed;}
  public void setRandomSeed (String RS){this.RandomSeed = RS;}
  
  public String getWinningHash() {return WinningHash;}
  public void setWinningHash (String WH){this.WinningHash = WH;}
  /*
  In order for us to verify the signature, we must know which public key to use, which will
  require us to know which process created the block. 
  */
  public String getCreationProcess() {return CreationProcess;}
  public void setCreationProcess (String CP){this.CreationProcess = CP;}
   /*
   This will store the signed Hash AFTER the puzzle has been solved. 
    */
  public String getCreatorSignedHash() {return CreatorSignedHash;}
  public void setCreatorSignedHash (String CSH){this.CreatorSignedHash = CSH;}

  public String getCreatorHash() {return CreatorHash;}
  public void setCreatorHash (String CH){this.CreatorHash = CH;}

  public String getBlockNum() {return BlockNum;}
  public void setBlockNum (String BN){this.BlockNum = BN;}

  



}



class PublicKeyWorker extends Thread { 
	/*
	This is a server that receives public keys from each process. The key is assumed to have 
	two pieces of information, the PID from the sending process as well as the public key
	from that process. The keys are then stored in their respective pID's index of an array.
	*/
  Socket sock; 
  PublicKeyWorker (Socket s) {sock = s;} 
  public void run(){
    try{
      BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
      String[] data;
     //The Data is read-in in one line. Then split knowing the pID is being stored before the space. 
      data = in.readLine ().split(" ");
      int pID= Integer.parseInt(data[0]);//String is moved into int for index purposes
     
     //now to decode the key and make it a "correct" key
      byte[] bytePubkey2  = Base64.getDecoder().decode(data[1]);
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubkey2);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);
      
      Blockchain.keyList[pID]= RestoredKey;//key is added to correct index in the keyList array
      Blockchain.keyCount++;
      if (Blockchain.keyCount==3) Blockchain.keyFlag=true;
      System.out.println("Got key for Process: " + pID);//writes to console

      sock.close(); 
    } catch (Exception x){x.printStackTrace();}
  }
}

class PublicKeyServer implements Runnable {
    
  public void run(){
    int q_len = 6;
    Socket sock;
    System.out.println("Starting Key Server input thread using " + Integer.toString(Blockchain.KeyServerPort));
    try{
      ServerSocket servsock = new ServerSocket(Blockchain.KeyServerPort, q_len);
      while (true) {
	sock = servsock.accept();
	new PublicKeyWorker (sock).start(); 
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

class UnverifiedBlockServer implements Runnable {
	/*
	This is our unverified block server that receives the initial blocks that were read in to each process 
	as well as any blocks that need to be RE-verified on account of a blockchain change. 
	*/
  BlockingQueue<BlockRecord> queue;
  UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
    this.queue = queue; 
  }

  class UnverifiedBlockWorker extends Thread { 
    Socket sock; 
    UnverifiedBlockWorker (Socket s) {sock = s;} 
    public void run(){
      try{
    
	BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	Gson gson = new Gson();
	StringBuffer sb = new StringBuffer();
	String InputLineStr;
	while ((InputLineStr=in.readLine())!=null){
		 sb.append(InputLineStr);
		}
	BlockRecord blockRecordIn = gson.fromJson(sb.toString(), BlockRecord.class);
	System.out.println("Put in priority queue: " + blockRecordIn.getBlockID() + "\n");
	Blockchain.queue.put(blockRecordIn);
	sock.close(); 
	
      } catch (Exception x){x.printStackTrace();}
    }
  }
  
  public void run(){
    int q_len = 10; // I increased this number just in case more than one block shows up at a time.
    Socket sock;
    System.out.println("Starting the Unverified Block Server input thread using " +
		       Integer.toString(Blockchain.UnverifiedBlockPort));
    try{
      ServerSocket servsock = new ServerSocket(Blockchain.UnverifiedBlockPort, q_len);
      while (true) {
	sock = servsock.accept(); // Got a new unverified block
	new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}


class UpdatedBlockWorker extends Thread {
	/*
	This is our UpdatedBlockWorker that will receive verified blocks from all processes. Once a connection is established
	the block is sent and read in using Json. The block is checked to ensure it hasn't already been added to the ledger and 
	if it hasn't, then it is Added to the blocks ledger. IF this is process 0, then entire ledger is then written to disk.
	*/
  Socket sock; // Class member, socket, local to Worker.

  UpdatedBlockWorker (Socket s) {
 	sock = s;
  } // Constructor, assign arg s to local sock
  public void run(){
    try{
      BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
      Gson gson = new Gson();
	  StringBuffer sb = new StringBuffer();
	  String InputLineStr;
	  while ((InputLineStr=in.readLine())!=null){
		   sb.append(InputLineStr);
		}
	BlockRecord blockRecordIn = gson.fromJson(sb.toString(), BlockRecord.class);
	if (!Blockchain.checkDupes(blockRecordIn))//verifies that block isn't already in ledger 
	{
		Blockchain.verifiedBlocks.add(0, blockRecordIn);//adds block to this processes ledger.
		System.out.println("Block added. Verified Count is: "+ Blockchain.verifiedBlocks.size());
		
	}
	if (Blockchain.pID==0){
		Blockchain.writeJSON();
	}
	
      sock.close(); 
    } catch (IOException x){x.printStackTrace();}
  }
}
class UpdatedBlockServer implements Runnable{
	public void run(){
    int q_len = 10;
    Socket sock;
    System.out.println("Starting UpdatedBlockServer input thread using " + Integer.toString(Blockchain.BlockChainPort));
    try{
      ServerSocket servsock = new ServerSocket(Blockchain.BlockChainPort, q_len);
      while (true) {
	sock = servsock.accept();
	new UpdatedBlockWorker (sock).start(); 
      }
    }catch (IOException ioe) {System.out.println(ioe);}


}
}
class Comparing implements Comparator<BlockRecord> //This is utility code for our Queue to arrange by timestamp.
    {
     @Override
     public int compare(BlockRecord b1, BlockRecord b2)
     {
      String s1 = b1.getTimeStamp();
      String s2 = b2.getTimeStamp();
      if (s1 == s2) {return 0;}
      if (s1 == null) {return -1;}
      if (s2 == null) {return 1;}
      return s1.compareTo(s2);
     }
    };

class Work implements Runnable{
	/*
	This is the Work section of the blockchain. The record is removed from the queue and placed in a temporary 
	Blockrecord variable (just in case the queue changes for some reason.) The record is then turned into a string.
	The signature of the block is then verified to ensure it has been signed by a process and that the signature checks out.
	"Work" is then done to verify the block and if the requirement is met, then it checks to ensure the blockChain has not 
	been updated by checking the previous hash of the top block in the ledger (newest.) If it HAS changed
	then the current block needs to be re-verified so it is sent back to the processes. If the blockchain has 
	not been changed, then it considered successfully verified and added to the blockchain and sent to each process.
	*/
  
    public static String ByteArrayToString(byte[] ba){
    	//This is utility code that takes a ByteArray argument and converts it to a string. 
	StringBuilder hex = new StringBuilder(ba.length * 2);
	for(int i=0; i < ba.length; i++){
	    hex.append(String.format("%02X", ba[i]));
	}
	return hex.toString();
    }

    public static String randomAlphaNumeric(int count) {
    	/*
    	This is utility code that creates a randomAN from the given count
    	*/
	StringBuilder builder = new StringBuilder();
	while (count-- != 0) {
	    int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
	    builder.append(ALPHA_NUMERIC_STRING.charAt(character));
	}
	return builder.toString();
    }
  
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";//pool of AN to pull from
    BlockingQueue<BlockRecord> queue;//creates a queue for this class
    static String randString;//wills store the randString

    Work(BlockingQueue<BlockRecord> queue){
    this.queue = queue; // This constructor gets the queue from Main and stores it in the queue created above.
  }
  
    public void run(){

    

	try {
	while(true){//will continue running. 

	BlockRecord tempRec= Blockchain.queue.take();//BlockRecord is pulled from the queue(no longer exists in queue)
	//a string of the record is created to be used in the digest hash in  String UB.
	String record=tempRec.getBlockID()+tempRec.getFname()+tempRec.getLname()+tempRec.getSSNum()+
			tempRec.getDOB()+tempRec.getDiag()+tempRec.getTreat()+tempRec.getRx()+ tempRec.getCreationProcess();

	String concatString = "";  // This will store UB and Random string in work section
	String stringOut = ""; //Will hold string created from hash 
	boolean hashVerified;
	boolean blockIDVerified;
	if (Blockchain.checkDupes(tempRec)&& tempRec!=null){
		System.out.println("Block already in BlockChain");
		continue;
	}

	hashVerified= Blockchain.verifySig(tempRec.getCreatorHash().getBytes(), Blockchain.keyList[Integer.valueOf(tempRec.getCreationProcess())],
		Base64.getDecoder().decode(tempRec.getCreatorSignedHash()));
	
	blockIDVerified = Blockchain.verifySig(tempRec.getBlockID().getBytes(), Blockchain.keyList[Integer.valueOf(tempRec.getCreationProcess())],
		Base64.getDecoder().decode(tempRec.getSignedBlockID()));
	if (!hashVerified){
		System.out.println("HASH NOT SIGNED");
	}
	else if (hashVerified){
		System.out.println("HASH SIGNED");
	}
	if (!blockIDVerified){
		System.out.println("BLOCK ID NOT SIGNED");
	}
	else if (blockIDVerified){
		System.out.println("BLOCK ID SIGNED");
	}


	randString = randomAlphaNumeric(8);//MAY NEED TO BE REMOVED.
	
	String previousID=Blockchain.verifiedBlocks.get(0).getBlockID();

	int workNumber = 0;     // This will store our work value and be used to determine if puzzle is solved
	
	String UB=record;//adds receord to UB 
	UB+=Blockchain.verifiedBlocks.get(0).getWinningHash();//adds winning hash to string UB Part of the "three" pieces of data
	//randString = randomAlphaNumeric(8);//unsure why this is in the work section twice, but leaving it. 
	if (!Blockchain.checkDupes(tempRec)&& tempRec!=null){
	try {
		

	    for(int i=1; i<20; i++){ // Limit how long we try for this example.
		randString = randomAlphaNumeric(8); // Get a new random AlphaNumeric seed string
		concatString = UB + randString; // Concatenate with our input string (which represents Blockdata)
		MessageDigest MD = MessageDigest.getInstance("SHA-256");
		byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value
	
		
		stringOut = ByteArrayToString(bytesHash); // Turn into a string of hex values, java 1.9  

		workNumber = Integer.parseInt(stringOut.substring(0,4),16); // Between 0000 (0) and FFFF (65535)
		
		if (!(workNumber < 20000)){  // if threshold is not met, then go again.
		    System.out.format("Unsolved \n");
		}
		if (workNumber < 20000){//threshold is met
		//System.out.println("Winning Random String after SOLVE "+ randString);
    		  if (previousID!=Blockchain.verifiedBlocks.get(0).getBlockID()){
      	/*
      	This checks the previous BlockID to ensure that it is the same blockID when started. AKA the blockchain has not 
      	changed. If it HAS changed, then we must send block back through. 
      	*/
        System.out.println("Readding from Work Loop");
        Blockchain.sendBlock(tempRec, "reAdd");
        
      				}
    
    		  else {
      	//if blockchain has not changed, then the block will be added to the ledger and broadcast
      	//information is set appropriately. 
      	tempRec.setWinningHash(stringOut);
  		tempRec.setRandomSeed(randString);
  		//System.out.println("Winning Random String being added "+ randString);
  		tempRec.setPreviousHash(Blockchain.verifiedBlocks.get(0).getWinningHash());
  		
  		//get previous blocks number so it can be incremented and added
  		int blockNum=Integer.valueOf(Blockchain.verifiedBlocks.get(0).getBlockNum());
  		blockNum++;
  		tempRec.setBlockNum(String.valueOf(blockNum));
  		tempRec.setVerificationProcessID(String.valueOf(Blockchain.pID));

  		//Signing winning hash with verifier signature
  		String signedVerifierHash="";

  		byte[] digitalSignature2 = Blockchain.signData(stringOut.getBytes(), Blockchain.keyPair.getPrivate());
    	signedVerifierHash=Base64.getEncoder().encodeToString(digitalSignature2);


		tempRec.setSignedWinningHash(signedVerifierHash);

  		//System.out.println("Previous ID is now:" + Blockchain.verifiedBlocks.get(0).getBlockID());

        Blockchain.verifiedBlocks.add(0,tempRec);
        
        System.out.println("Block Added. Verified Count is: "+ Blockchain.verifiedBlocks.size());
        Blockchain.sendBlock(tempRec, "sendUpdate");
        //multicast block to other processes
       			 continue;
    			  }
		    break;
		}
		
		if (Blockchain.checkDupes(tempRec)){
			//This checks periodically that the current block that we are working on isn't a duplicate. If so, 
			//we abandon. 
      		System.out.println("It's a Dupe in Work Loop");
      	 	break;
    	}
    try{Thread.sleep(1000);}catch(Exception e){}
	    }
	}catch(Exception ex) {ex.printStackTrace();}
	
	}

	//left this code in if we want the process to stop, otherwise, it will keep waiting for data
	} 
		}catch(Exception ex) {ex.printStackTrace();}
		System.out.println("LOOP STOPPED");//for debugging purposes to see if loop is ended for some reason. 
    }
}



class StartServerWorker extends Thread {
	/*
	This is the server used to receive the start command from Process 2 and change the 
	startFlag to TRUE which allows the processes to continue through the mainThread. 
	*/
  Socket sock; 

  StartServerWorker (Socket s) {
 	sock = s;
  } 
  public void run(){
    try{
      BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
      //simply gets input string and once received, changes the flag to true. This assumes there are 
      //no other commands going to be sent to this server. May add more precision later. 
      String data = in.readLine ();
      Blockchain.startFlag=true;
      sock.close(); 
    } catch (IOException x){x.printStackTrace();}
  }
}
class StartServer implements Runnable{
	public void run(){
    int q_len = 6;
    Socket sock;
    System.out.println("Start Server Activate at " + Integer.toString(Blockchain.StartServerPort));
    try{
      ServerSocket servsock = new ServerSocket(Blockchain.StartServerPort, q_len);
      while (true) {
	sock = servsock.accept();
	new StartServerWorker (sock).start(); 
      }
    }catch (IOException ioe) {System.out.println(ioe);}


}
}





public class Blockchain {
	public static int pID;//stores our Process ID for THIS process
	public static String inFile;//will store read-in file
	public static int UnverifiedBlockPort;
	public static int BlockChainPort;
	public static int KeyServerPort;
	public static int StartServerPort;
	public static int KeyServerPortBase = 4710;
	public static int UnverifiedBlockServerPortBase = 4820;
	public static int UpdatedBlockchainServerPortBase = 4930;
	public static int StartServerPortBase = 4600;
	public static int numProcesses = 3;//stores number of process. This could easily be updated for more
	static String serverName = "localhost";//this could be updated to support a more sophisticated implementation
	public static PublicKey pubKey;
	public static KeyPair keyPair;//This will store our key pair for this process.
	public static boolean startFlag=false;//This is the variable that will be updated when processes can start
	public static boolean keyFlag=false;
	public static int keyCount=0;
	public static boolean inputFlag=false;
	
	static LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();//this will store our records (unverified blocks) for the process
  	public static final BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<BlockRecord>(30, new Comparing()); //This is our queue for work
  	public static PublicKey[] keyList=new PublicKey[numProcesses];//This will store our array of public keys
  	public static LinkedList<BlockRecord> verifiedBlocks= new LinkedList<BlockRecord>();//this is our blockchain ledger
  	


	 /* Utility code for storing indexes used for creating blocks */
  private static final int iFNAME = 0;
  private static final int iLNAME = 1;
  private static final int iDOB = 2;
  private static final int iSSNUM = 3;
  private static final int iDIAG = 4;
  private static final int iTREAT = 5;
  private static final int iRX = 6;
  


	public static void main(String args[]){
    int q_len = 6; // number of requests to queue if simultaneous 
    if (args.length < 1) pID = 0; //if we aren't given an arg. then use 0
    else if (args[0].equals("0")) 
    	pID = 0;
    else if (args[0].equals("1")) 
    	pID = 1;
    else if (args[0].equals("2")) 
    	pID = 2;
    else 
    	pID = 0; //this is added to account for bad formatting or errors with argument

    UnverifiedBlockPort = UnverifiedBlockServerPortBase + pID;//creates unique port for this specific process' unverified BC
    BlockChainPort = UpdatedBlockchainServerPortBase + pID;//creates unique port for verified BC
    KeyServerPort=	KeyServerPortBase + pID;
    StartServerPort=StartServerPortBase + pID;


    inFile=String.format("BlockInput%d.txt",pID);//creates fileName string for input


    System.out.println("We are accessing file " + inFile);

    new Thread(new StartServer()).start();
    new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
    new Thread(new UnverifiedBlockServer(queue)).start(); // New thread to process incoming unverified blocks
    new Thread(new UpdatedBlockServer()).start(); // New thread to process incomming new blockchains
    try{Thread.sleep(2000);}catch(Exception e){}
    
    
    if (pID==2){
    	sendStartSignal();
    }



    try{ 
    	keyPair = generateKeyPair(444);
    } catch (Exception e){}

    while (!startFlag){try{Thread.sleep(1000);}catch(Exception e){}}
    System.out.println("Now Starting");
	multiCastKeys();
	while (!keyFlag){try{Thread.sleep(1000);}catch(Exception e){}}
	
	if (pID==0)
		dummyBlock();
    readFile();
    multiCast();

    try{Thread.sleep(2000);}catch(Exception e){}

    new Thread(new Work(queue)).start();

   try{Thread.sleep(15000);}catch(Exception e){};
    System.out.println("Initial Verification is complete. You may now use keys (V) Verify whole BlockChain (C) Credits or (L) Print Lines of Records");
    System.out.println("(R + fileName) to read different file\n");
    while(true){
    	System.out.println("Enter Command Now:\n");
    	Scanner input=new Scanner(System.in);

    	String response=input.nextLine();

    	if (response.equals("C")|| response.equals("c"))
    		credit();
    	else if (response.equals("V") || response.equals("v"))
    		verifyBC();
    	else if (response.equals("L") || response.equals("l"))
    		printRecords();
    	else if (response.contains("r") || response.contains("R")){
    		String[] tokens=response.split(" ");
    		String fileName=tokens[1].substring(0);
    		readDifferent(fileName);
    		
    	}


    }
    

    }



    public static boolean sendStartSignal(){
    	/*
    	This is the method used by Process 0 to send a "start" signal to each of the processes. Once received,
    	they change the startFlag which allows them to continue through the method calls in Main.
    	*/
    Socket sock;
    PrintStream toServer;
   
    try{
      for(int i=0; i< numProcesses; i++){
    
	sock = new Socket(serverName, StartServerPortBase + i);
	toServer = new PrintStream(sock.getOutputStream());
	toServer.println("start");//sends start command to server. 
	System.out.println("Sending Start");
	toServer.flush();
	sock.close();
      }
      
      
     
 	}catch (Exception e){e.printStackTrace();}
 	return true;
}



 	public static void sendBlock(BlockRecord record, String command){
 		/*
 		This method is used as to send Blocks. If the block is verifed and ready to be added to the ledger, 
 		then the sendUpdate command is used and sent to the updatedBlockchainServerPort for each process.
 		If the block needs to be re-verified for whatever reason, then it is sent back to the unverifiedBlockServer 
 		of each process.
 		*/
    Socket sock;
    PrintStream toServer;
   	if (command.equals("sendUpdate")){
    try{
      for(int i=0; i< numProcesses; i++){// Send a sample unverified block A to each server
    
	sock = new Socket(serverName, UpdatedBlockchainServerPortBase + i);
	toServer = new PrintStream(sock.getOutputStream());

	toServer.println(buildString(record));//uses my buildString function to marshall record as JSON
	System.out.println("Broadcasting Verified Block " + record.getBlockID());
	toServer.flush();
	sock.close();
      }   
     
 	}catch (Exception e){e.printStackTrace();}}
 	else if (command.equals("reAdd")){
 		try{

      for(int j=0; j< numProcesses; j++){// Send a sample unverified block A to each server 
	sock = new Socket(serverName, UnverifiedBlockServerPortBase + j);
	toServer = new PrintStream(sock.getOutputStream());
	toServer.println(buildString(record));//insert fake block here
	System.out.println("Broadcasting block " + record.getBlockID());
	toServer.flush();
	sock.close();
      }
      
     
 	}catch (Exception e){e.printStackTrace();}}

 	}
 

    public static void multiCastKeys(){
    /*
    This is mostly utility code that gets the public key and broadcasts the key to each of the processes. 
    Each key sent has an additional piece of information (processID.) This way it can be stored in an array
    and we can decide which publicKey to use when verifying. 
    */
    Socket sock;
    PrintStream toServer;
    byte[] bytePubkey = keyPair.getPublic().getEncoded();
    String stringKey = Base64.getEncoder().encodeToString(bytePubkey);
    System.out.println("Created Key: " + stringKey);
    try{
      for(int i=0; i< numProcesses; i++){
	sock = new Socket(serverName, KeyServerPortBase + i);
	toServer = new PrintStream(sock.getOutputStream());
	String toSend=pID + " " + stringKey;
	toServer.println(toSend);
	toServer.flush();
	sock.close();
     	 }
  	   } catch (Exception e){e.printStackTrace();}
    }
    


     public static KeyPair generateKeyPair(long seed) throws Exception {
     	//This is utility code that creates a pair of key(Public and Private)
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rng.setSeed(seed);
    keyGenerator.initialize(1024, rng);
    
    return (keyGenerator.generateKeyPair());
  }


  public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
  	//This is utility code that signs data using privateKey
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initSign(key);
    signer.update(data);
    return (signer.sign());
  }

 public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
 	//This is utility code to allow our process to verify that data is signed using Publickey.
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initVerify(key);
    signer.update(data);
    
    return (signer.verify(sig));
  }

 public static void dummyBlock(){
 		/*
 		This is the dummyBlock that will serve as the starting point for each process.
 		The data is set so that each block receives the same data. 
 		*/
 		BlockRecord  block = new BlockRecord();
 		String suuid;
 		String SHA256String = "";
 		
    	
    	Date date = new Date();
		long time=date.getTime();
		String T1=String.valueOf(time);
		String TimeStampString = T1 + "." + pID;
		suuid = new String(UUID.randomUUID().toString());
		block.setTimeStamp(TimeStampString);
		block.setBlockID(suuid);
		block.setFname("Einstein");
		block.setLname("Kennedy");
		block.setSSNum("999-00-9999");
		block.setDOB("1900.01.01");
		block.setDiag("Death");
		block.setTreat("Alive");
		block.setRx("BringBack2Life");
		block.setPreviousHash("9999999999");
		block.setBlockNum("1");
		//creates string of all block elements to be used to create SHA256 Hash.
		String record=block.getBlockID()+block.getFname()+block.getLname()+block.getSSNum()+
			block.getDOB()+block.getDiag()+block.getTreat()+block.getRx();

    	try{
      MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
      ourMD.update (record.getBytes());
      byte byteData[] = ourMD.digest();

      
      StringBuffer sb = new StringBuffer();
      for (int i = 0; i < byteData.length; i++) {
		sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
      }
      SHA256String = sb.toString(); 
      block.setWinningHash(SHA256String);
    }catch(NoSuchAlgorithmException x){};

   	verifiedBlocks.add(0, block);
   	
   	System.out.println("Size is now: "+ verifiedBlocks.size());
   	if(pID==0){
   		//this allows the dummyBlock to get written to the block ledger. 
   		System.out.println("Writing Block One");
   		sendBlock(block, "sendUpdate");
   	writeJSON();
   }
   	
 }



	public static void multiCast (){ 
	/*
	This multiCast function is primarily from utility code. It functions to send unverified blocks to each 
	of the processes so that each one can compete to verify ALL blocks from ALL processes. 
	*/
    Socket sock;
    PrintStream toServer;
   	BlockRecord tempRec;
   	Iterator<BlockRecord> iterator = recordList.iterator();//created so that list can be iterated over. 
    try{

    while (iterator.hasNext()){
    	tempRec = iterator.next();
    	String record=buildString(tempRec);//uses buildString method to create Json string. 
      for(int i=0; i< numProcesses; i++){// Send a sample unverified block A to each server
    
	sock = new Socket(serverName, UnverifiedBlockServerPortBase + i);//a connection is established to EACH process

	toServer = new PrintStream(sock.getOutputStream());

	toServer.println(record);
	toServer.flush();
	sock.close();
      }
      
     }
 }catch (Exception e){e.printStackTrace();}
  }
  public static String buildString(BlockRecord temp){
  	/*
  	I created this method to help clean up some of the code since the following code was used a lot for 
  	marshalling data using Json. The record is passed as an argument (Temp) and is placed in a Json string. 
  	*/
    	Gson gson = new GsonBuilder().setPrettyPrinting().create();
    	String json = gson.toJson(temp);

    	return json;
    }

   public static boolean checkDupes(BlockRecord record){
   	/*
   	This is a method that checks the Blockchain ledger to see if the passed argument is already in the 
   	ledger. 
   	*/
   		BlockRecord tempRec=record;
   		Iterator<BlockRecord> iterator = verifiedBlocks.iterator();//an iterator of the verifiedBlocks is created
   		while(iterator.hasNext()){
   			//the passed record's blockID is checked against each block in the ledger and if it matches
   			//then it is a duplicate. 
   			if (tempRec.getBlockID().equals(iterator.next().getBlockID()))
   				return true;
   		}
   		return false;
   }

	public static void writeJSON(){
		/*
		This method allows process 0 to write to disk the entire Blockchain ledger. Each time a new block is added 
		and received, process 0 writes the ENTIRE ledger. VerifiedBlocks is the stored LinkedList of 
		verified blocks to be added to the ledger. 
		*/
    System.out.println("=========> In WriteJSON <=========\n");
    //create gson instance to get verifiedBlocks and place in string for printing to disk. 
    Gson gson = new GsonBuilder().setPrettyPrinting().create();

    
    String json = gson.toJson(verifiedBlocks);
   	//this attempts to write to a file named blockRecord.json
    try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
      gson.toJson(verifiedBlocks, writer);//this writes the ENTIRE Ledger each time. 
    } catch (IOException e) {
      e.printStackTrace();
    }
  }


	public static void readFile(){
		/*Reads input of information from txt file. It then creates tokens of the data read in 
		and uses the known token indexes to input the data into the unverified block. 
		Each block has a SHA256 hash string created that creates a signature of to later 
		be verified and ensure the block is signed. 
		
		*/
	 try{ BufferedReader br = new BufferedReader(new FileReader(inFile));

      String[] tokens = new String[10];//creates tokens of to place the input string. 
      String InputLineStr;//this is the string to store the ENTIRE input of text. 
      String suuid;//will store the unique blockID 
     
      
     
    try {
    	while ((InputLineStr=br.readLine()) !=null){

    		BlockRecord  block = new BlockRecord();
    		
    		Date date = new Date();//creates an instance of the date. 
    		long time=date.getTime();//This is used to create a longer version of time so that there is better accuracy
    		String T1=String.valueOf(time);//creates string of time in Milliseconds. 
    		String TimeStampString = T1 + "." + pID ;//adds Process ID to end of time to ensure there are no collisions.
    		suuid = new String(UUID.randomUUID().toString());//creates random block ID
    		tokens = InputLineStr.split(" +"); // This breaks up the input into tokens and stores in String[]
    		//Below are where elements of information are added to unverified block.
    		String signedBlockID="";
    		try{
    		byte[] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
    		signedBlockID=Base64.getEncoder().encodeToString(digitalSignature);

    		 }catch(Exception x){};
    		

    		block.setTimeStamp(TimeStampString);
    		block.setBlockID(suuid);
    		block.setSignedBlockID(signedBlockID);
			block.setFname(tokens[iFNAME]);
			block.setLname(tokens[iLNAME]);
			block.setSSNum(tokens[iSSNUM]);
			block.setDOB(tokens[iDOB]);
			block.setDiag(tokens[iDIAG]);
			block.setTreat(tokens[iTREAT]);
			block.setRx(tokens[iRX]);
			block.setCreationProcess(String.valueOf(pID));
			//block is then added to the record list (unverified blocks) Type: BlockRecord
			recordList.add(block);
			//A string of the block is then created to be used blow to make a hash Digest.
			String record=block.getBlockID()+block.getFname()+block.getLname()+block.getSSNum()+
			block.getDOB()+block.getDiag()+block.getTreat()+block.getRx()+ block.getCreationProcess();
			//System.out.println(record);

		

    
    
    String SHA256String = "";//This will store the hash digest string. 
    /*
    The block is used to create a hash digest that will be used to verify that the block is 
    properly signed by a process. 
    */
    String signedHash = "";
    try{
      MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
      ourMD.update (record.getBytes());
      byte byteData[] = ourMD.digest();

      // CDE: Convert the byte[] to hex format. THIS IS NOT VERFIED CODE:
      StringBuffer sb = new StringBuffer();
      for (int i = 0; i < byteData.length; i++) {
		sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
      	}
      SHA256String = sb.toString(); // For ease of looking at it, we'll save it as a string.
    }catch(NoSuchAlgorithmException x){};


    try{
    		byte[] digitalSignature2 = signData(SHA256String.getBytes(), keyPair.getPrivate());
    		signedHash=Base64.getEncoder().encodeToString(digitalSignature2);

    		 }catch(Exception x){};
    block.setCreatorHash(SHA256String);
    block.setCreatorSignedHash(signedHash);
			try{Thread.sleep(500);} catch(Exception e){}

    	}
    } catch (IOException e) {
      e.printStackTrace();
  	}
  		} catch(FileNotFoundException e){
	 	e.printStackTrace();
	 	}
	}

	public static void verifyBC(){
		/*
		The Blockchain Ledger is read in and stored in a temporary verifyList. The list is iterated (skipping the dummy block.)
		The block data, SHA 256 and randomSeed are concatenated into a string. The string is then used to create another SHA-256 
		hash that is compared to the Winning HASH found in the block. If the hash is the same, then it passes the first "verification."
		It is then formed into a "worknumber" to ensure it passes the puzzle. The signatures are then verified. 
		*/
		 Gson gson = new Gson();
		 LinkedList<BlockRecord> verifyList = new LinkedList<BlockRecord>();
		 boolean failure=false;
		 String line;
		 try (Reader reader = new FileReader("BlockchainLedger.json")) {
		 		
		 		Type type = new TypeToken<LinkedList<BlockRecord>>(){}.getType();
		 		verifyList=gson.fromJson(reader, type);
		 		
		 		Iterator<BlockRecord> iterator = verifyList.iterator();//created so that list can be iterated over. 
    			

    			while (iterator.hasNext()){
    					BlockRecord tempRec = iterator.next();
    				 
		 			//skipping the dummy block due to pseudo data
		 			if (tempRec.getBlockNum().equals("1")){
		 				continue;
		 			}
		 			else{
		 				String SHA256String = "";
		 				String stringOut;

		 				String record=tempRec.getBlockID()+tempRec.getFname()+tempRec.getLname()+tempRec.getSSNum()+
			tempRec.getDOB()+tempRec.getDiag()+tempRec.getTreat()+tempRec.getRx()+ tempRec.getCreationProcess();

						int previousBlockNum=Integer.valueOf(tempRec.getBlockNum());
						 try{
						

						
						
						
						String UB=record;//adds receord to UB 
						UB+=tempRec.getPreviousHash();//add previous hash

						
						//creation of SHA 256 digest
						String concatString = UB + tempRec.getRandomSeed(); // Concatenate with our input string (which represents Blockdata)
						MessageDigest MD = MessageDigest.getInstance("SHA-256");
						byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value
	
						
						stringOut = Work.ByteArrayToString(bytesHash); // Turn into a string of hex values, java 1.9  
      					 
      					SHA256String=stringOut;
						int workNumber = Integer.parseInt(stringOut.substring(0,4),16);	
						if (!(workNumber < 20000)){
							System.out.println("Puzzle Not solved\n");
							failure=true;
						}

						//System.out.println(workNumber);
						if (!stringOut.equals(tempRec.getWinningHash())){
							System.out.println("Hash Verification Failed\n");
							failure=true;
						}
						try{
						boolean hashVerified= verifySig(tempRec.getWinningHash().getBytes(), 
							keyList[Integer.valueOf(tempRec.getVerificationProcessID())],
							Base64.getDecoder().decode(tempRec.getSignedWinningHash()));
	
						boolean blockIDVerified = verifySig(tempRec.getBlockID().getBytes(), 
							keyList[Integer.valueOf(tempRec.getCreationProcess())],
							Base64.getDecoder().decode(tempRec.getSignedBlockID()));

						if (!hashVerified){
							System.out.println("HASH SIGNATURE VERIFICATION FAILED\n");
							failure=true;
						}
						if (!blockIDVerified){
							System.out.println("BLOCKID SIGNATURE VERIFICATION FAILED\n");
							failure=true;
						}



					} catch (Exception e) { e.printStackTrace(); }





						}catch(NoSuchAlgorithmException x){};
		 			}



		 		}

		 	} catch (IOException e) { e.printStackTrace(); }
		 	if (!failure) System.out.println("ALL CHECKS COMPLETED. BLOCKCHAIN VERIFIED\n");
		 	else if (failure) System.out.println("FAILURE ALERT!\n");


	}

	public static void credit(){
		/*
		This method is used when a user enters 'c.' It iterates through the ledger and tallies the counts for 
		each verification process.  
		*/
		Gson gson = new Gson();
		 LinkedList<BlockRecord> verifyList = new LinkedList<BlockRecord>();
		 int credit[]=new int[numProcesses];
		 
		 String line;
		 try (Reader reader = new FileReader("BlockchainLedger.json")) {
		 		
		 		Type type = new TypeToken<LinkedList<BlockRecord>>(){}.getType();
		 		verifyList=gson.fromJson(reader, type);
		 		
		 		Iterator<BlockRecord> iterator = verifyList.iterator();//created so that list can be iterated over. 
    			

    			while (iterator.hasNext()){
    					BlockRecord tempRec = iterator.next();
    					if (tempRec.getVerificationProcessID()!=null){
    					int processNum=Integer.valueOf(tempRec.getVerificationProcessID());
    					credit[processNum]++;//increment at index of processNum
    				 
		 			
		 		}

		 		}

		 		System.out.printf("Process 0 Credit: %d \nProcess 1 Credit: %d\nProcess 2 Credit: %d\n", credit[0], credit[1], credit[2]);

		 	} catch (IOException e) { e.printStackTrace(); }


	}

  public static void printRecords(){
  	/*
  	This method is executed when a user types (L.) It reads the JSON ledger and creates a temporary list. The list is then iterated 
  	and the information from the block is printed on a single line.
  	*/
    Gson gson = new Gson();
     LinkedList<BlockRecord> verifyList = new LinkedList<BlockRecord>();
     
     
     String line;
     try (Reader reader = new FileReader("BlockchainLedger.json")) {
        
        Type type = new TypeToken<LinkedList<BlockRecord>>(){}.getType();
        verifyList=gson.fromJson(reader, type);
        
        Iterator<BlockRecord> iterator = verifyList.iterator();//created so that list can be iterated over. 
          

          while (iterator.hasNext()){
            BlockRecord tempRec=iterator.next();
            System.out.printf("%s %s %s %s %s %s %s %s \n", tempRec.getTimeStamp(), tempRec.getFname(),
            tempRec.getLname(), tempRec.getDOB(), tempRec.getSSNum(), tempRec.getDiag(), tempRec.getTreat(), tempRec.getRx() );  
             
          
      
        }

        

      } catch (IOException e) { e.printStackTrace(); }

  }
  public static void readDifferent(String fileName){
		/*
		After a user enters (R) and a fileName(possibly filePath is necessary as well) then it will read the file and add the new blocks.
		This is extremely similar to the original readFile code but takes an argument.
		*/
		System.out.println("Attempting to open"+ fileName);
	 try{ BufferedReader br = new BufferedReader(new FileReader(fileName));

      String[] tokens = new String[10];//gets separate tokens for block.
      String InputLineStr;//this will store the input of the block.
      String suuid;
     
      
     
    try {
    	while ((InputLineStr=br.readLine()) !=null){

    		BlockRecord  block = new BlockRecord();
    		
    		Date date = new Date();
    		long time=date.getTime();
    		String T1=String.valueOf(time);
    		String TimeStampString = T1 + "." + pID ;
    		suuid = new String(UUID.randomUUID().toString());
    		tokens = InputLineStr.split(" +"); 
    		String signedBlockID="";
    		try{
    		byte[] digitalSignature = signData(suuid.getBytes(), keyPair.getPrivate());
    		signedBlockID=Base64.getEncoder().encodeToString(digitalSignature);

    		 }catch(Exception x){};
    		

    		block.setTimeStamp(TimeStampString);
    		block.setBlockID(suuid);
    		block.setSignedBlockID(signedBlockID);
			block.setFname(tokens[iFNAME]);
			block.setLname(tokens[iLNAME]);
			block.setSSNum(tokens[iSSNUM]);
			block.setDOB(tokens[iDOB]);
			block.setDiag(tokens[iDIAG]);
			block.setTreat(tokens[iTREAT]);
			block.setRx(tokens[iRX]);
			block.setCreationProcess(String.valueOf(pID));
			//block gets added to list
			recordList.add(block);
			//We perform the same steps as the original blocks below.
			String record=block.getBlockID()+block.getFname()+block.getLname()+block.getSSNum()+
			block.getDOB()+block.getDiag()+block.getTreat()+block.getRx()+ block.getCreationProcess();
			//System.out.println(record);

		

    
    
    String SHA256String = "";
    /*
    This is the same HASH digest process for other blocks. 
    */
    String signedHash = "";
    try{
      MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
      ourMD.update (record.getBytes());
      byte byteData[] = ourMD.digest();

      
      StringBuffer sb = new StringBuffer();
      for (int i = 0; i < byteData.length; i++) {
		sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
      	}
      SHA256String = sb.toString(); 
    }catch(NoSuchAlgorithmException x){};


    try{
    		byte[] digitalSignature2 = signData(SHA256String.getBytes(), keyPair.getPrivate());
    		signedHash=Base64.getEncoder().encodeToString(digitalSignature2);

    		 }catch(Exception x){};
    block.setCreatorHash(SHA256String);
    block.setCreatorSignedHash(signedHash);
    sendBlock(block, "reAdd");//broadcasts to ALL processes the new blocks. Just using code intended for readding to queue.
			try{Thread.sleep(500);} catch(Exception e){}

    	}
    } catch (IOException e) {
      e.printStackTrace();
  	}
  		} catch(FileNotFoundException e){
	 	e.printStackTrace();
	 	}

	}


}









