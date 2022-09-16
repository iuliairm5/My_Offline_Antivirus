package IRIMIA.IULIAGABRIELA.ism.sap;

import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Assignment2_OfflineAntivirus_IRIMIA_IULIA_GABRIELA {
  //------------------------------------------------------------------------------------
    public static String getHex(byte[] array) 
    {
        String output= "";
        for(byte value :array) 
        {
            output += String.format("%02x",value);
        }
        return output;
    }

//---------------------------------------------------------------------------------------
    public static byte[] getHashMAC(String inputFileName,byte[] secretKey, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        
        byte[] hashMAC = null;
        //open the file, read chunks of it
        File file = new File(inputFileName);
        if(!file.exists())
        {
            throw new FileNotFoundException();
        }
        //create/init the MAC OBJECT to process the hashMAC
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretKey,algorithm));

        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis); 

        byte[] buffer = new byte[1024];//read 1K at a time 
        //PROCESS ONLY WHAT WE GOT FROM THE FILE
        int noBytesFromFile = bis.read(buffer); //the noBytes that we get from the file
        while(noBytesFromFile != -1)
        {
            mac.update(buffer,0,noBytesFromFile);//from offset 0 and how many bytes //process the file's content
            noBytesFromFile = bis.read(buffer);//to fill up again the buffer
        }
        //get the final result
        hashMAC = mac.doFinal(); //our HMAC (depends on the secretkey and the file content)
        bis.close();
        return hashMAC;
    }
//-----------------------------------------------------------------------------------------------
static ArrayList<String> filesWithHmacs = new ArrayList<String>(); //kind of a global variable to store paths+HMACs

public static void StatusUpdate(String path,String secretKey,String algorithm,File outputFile) throws InvalidKeyException, NoSuchAlgorithmException, IOException
{
    File folder=new File(path);
    if(folder.exists() && folder.isDirectory())
    {
        File[] entries = folder.listFiles();//an array of files
        for(File entry:entries)
        {
            if(entry.isDirectory()){
                StatusUpdate(entry.getAbsolutePath(),secretKey,algorithm,outputFile);
            }
            else{ //it's a file
                if(!entry.getName().equals("Status Update.txt")){ //i dont want to store also the HMAC of my Status Update file
                    //System.out.println(entry.getName());
                    //System.out.printf("\nAbsolutePath of file: %s ",entry.getAbsolutePath());
                    String newPath = entry.getAbsolutePath().replace("\\","\\\\"); //actually replacing \ with \\ on the path
                    //System.out.printf("\nnew path of file: %s ",newPath);
                    byte[] hmacFile = getHashMAC(newPath,secretKey.getBytes(),algorithm); //get the HMAC value of each file
                    //System.out.println("The hmac: " + getHex(hmacFile));
                    String dataStoredInFile = new String(entry.getAbsolutePath()+" => "+getHex(hmacFile));
                    //System.out.println("\nfile and its HMAC: "+dataStoredInFile);
                
                    filesWithHmacs.add(dataStoredInFile);
                } 
            }
        }
    }
    FileWriter fileWriter = new FileWriter(outputFile,false);
    PrintWriter printer = new PrintWriter(fileWriter);
    for (String string : filesWithHmacs) {
        printer.println(string);//write line by line in file
    }
    printer.close(); 
}
//----------------------------------------------------------------------------------------------
static ArrayList<String> filesWithNewHmacs = new ArrayList<String>(); //kind of a global variable to store paths+HMACs
static ArrayList<String> filesPaths = new ArrayList<String>(); //kind of a global variable to store only paths
public static void CheckIntegrity(String path,String secretKey,String algorithm,File reportFile,String statusFileName) throws InvalidKeyException, NoSuchAlgorithmException, IOException
{
    File folder=new File(path);
    if(folder.exists() && folder.isDirectory())
    {
        File[] entries = folder.listFiles();//an array of files
        for(File entry:entries)
        {
            if(entry.isDirectory()){
                CheckIntegrity(entry.getAbsolutePath(),secretKey,algorithm,reportFile,statusFileName);
            }
            else{ //it's a file
                if((!entry.getName().equals("Status Update.txt")) && (!entry.getName().contains("Report File"))){ //DONT WANT TO CHECK INTEGRITY OF ANY REPORT FILE OR STATUS UPDATE FILE
                    //System.out.printf("\nAbsolutePath of file: %s ",entry.getAbsolutePath());
                    String newPath = entry.getAbsolutePath().replace("\\","\\\\");
                    //System.out.printf("\nnew path of file: %s ",newPath);
                    byte[] hmacFile = getHashMAC(newPath,secretKey.getBytes(),algorithm); //get the HMAC value of each file
                    //System.out.println("The hmac: " + getHex(hmacFile));
                    String dataStoredInFile = new String(entry.getAbsolutePath()+" => "+getHex(hmacFile));
                    //System.out.println("\nfile and its HMAC: "+dataStoredInFile);
                    filesPaths.add(entry.getAbsolutePath());
                    filesWithNewHmacs.add(dataStoredInFile);
                }
            } 
        }
    }
    FileWriter fileWriter = new FileWriter(reportFile,false); //for writing in the Report File
    PrintWriter printer = new PrintWriter(fileWriter);
    File file = new File(statusFileName);
    FileReader reader = new FileReader(file); //for reading from the Status File
    BufferedReader reader2 = new BufferedReader(reader);

    //acesta varianta nu lua in calcul daca se stergeau sau se adaugau files in root path, dupa ultimul status update
    /*int i=0;
    String line = reader2.readLine(); //read the first line from the Status file
    for (String string : filesWithNewHmacs) {
        
        //System.out.println("line read from status file: "+line);
        if(line.equals(string))
        {
            String dataStoredInFile = new String(filesPaths.get(i)+" => "+"OK");
            printer.println(dataStoredInFile);
            
        }
        else{
            String dataStoredInFile = new String(filesPaths.get(i)+" => "+"CORRUPTED");
            printer.println(dataStoredInFile);
        }
        i++;
        if(line != null) {
            line = reader2.readLine();//read the next line from the status file
        }
    }
    */

    ///*
    //presupun ca inainte de checkintegrity se pot sterge files din root path sau se pot adauga noi files in root path; lucrez doar cu files care inca exista si au HMAC-ul salvat in ultimul status update.txt 
    //pentru fiecare line citit din status update.txt, caut printre pathurile citite la integrity check 
    String line = reader2.readLine();
    while(line != null)
    {
        for(int i=0;i<filesPaths.size();i++)
        {   
            if(line.contains(filesPaths.get(i))) //am matching la path (fisierul respectiv inca exista in root path)
                {
                    if(line.equals(filesWithNewHmacs.get(i)))
                    {
                        String dataStoredInFile = new String(filesPaths.get(i)+" => "+"OK");
                        printer.println(dataStoredInFile);
            
                    }
                    else{
                        String dataStoredInFile = new String(filesPaths.get(i)+" => "+"CORRUPTED");
                        printer.println(dataStoredInFile);
                        }
                    break ;//iesire din blockul for
                }
        }
         
        if(line != null) {
            line = reader2.readLine();//read the next line from the status file
            }
    }
//*/
    reader.close();
    printer.close(); 
}

//----------------------------------------------------------------------------------------------

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IOException
    {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n☆ Please type the root path without using the quotation marks and don't forget to include double backslash ! (for example: E:\\\\User\\\\Folder1\\\\Subfolder1) \n");
        String rootPath = scanner.nextLine();

        System.out.println("\n☆ Please type S for updating status or I for checking integrity :\n");
        String answer1 = scanner.nextLine();
        if(answer1.equals("S"))
        {
            System.out.println("\n☆ Please type the secret key :\n");
            String secretKey = scanner.nextLine();
            //System.out.printf("\nThe secret key is: %s",secretKey);
            System.out.println("\n☆ Please type the wanted algorithm (HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512) :\n");
            String algorithm = scanner.nextLine();
            //System.out.printf("\nThe algorithm is: %s",algorithm);
            File entry = new File(rootPath);
            if(entry.exists() && entry.isDirectory())
            {
                File outputFile = new File("Status Update.txt");
                outputFile.createNewFile();
                
                StatusUpdate(entry.getAbsolutePath(),secretKey,algorithm,outputFile);
    
            }
            scanner.close();
        }
        else if(answer1.equals("I"))
        {
            //check integrity
                System.out.println("\n☆ TIP: don't forget to type the exact same secret key and the algorithm used for status update !!");
                System.out.println("\n☆ Please type the secret key :\n");
                String secretKey = scanner.nextLine();
                System.out.println("\n☆ Please type the wanted algorithm (HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512) :\n");
                String algorithm = scanner.nextLine();
                //generate a text report
                File entry = new File(rootPath);
                if(entry.exists() && entry.isDirectory())
                    {
                    LocalDateTime myDateObj = LocalDateTime.now();
                    DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("dd-MM-yyyy HH-mm-ss");
                    String formattedDate = myDateObj.format(myFormatObj);
                
                    String reportFileName = new String("Report File "+formattedDate+".txt");
                    //System.out.println(reportFileName);
                
                    File reportFile = new File(reportFileName);
                    reportFile.createNewFile();

                    CheckIntegrity(entry.getAbsolutePath(), secretKey, algorithm, reportFile,"Status Update.txt");
                
                    }
            
        }
        else{
            System.out.println("\n☆ No operation mode !\n");
        }
        scanner.close();     
    }   
}

    

