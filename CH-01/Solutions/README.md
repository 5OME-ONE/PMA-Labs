# Static Analysis

## <span style="color:#004F98;">**Lap 01-01:**</span>.
1. Yup, 54/70 Antivirus have identified as malware (trojan).![virustotal](Images/Screenshot%202023-05-06%20004638.png)
2. Using **PEview** it shows that it was uploaded in 19/12/2010![PEview](Images/Screenshot%202023-05-06%20005149.png)
3. I can't find any indications that either file is packed or obfuscated, also **PEid** had idintified it as a microsoft visual C++ file.![Alt text](Images/11.png)


___

## <span style="color:#004F98;">**Lap 01-02:**</span>.
1. Same as the Previous one, 54/70 Antivirus have identified as malware (trojan).![virustotal](Images/2.png)
2. * first, using **peid** EP section tells us that it maybe packed using UPX1.![PEid](Images/22.png)
   * second, using **peview** it's obvious that there is there sections called UPX0, UPX1, UPX2 which mean it's packed. ![peview]Images/(222.png)
   * third, If you need to unpack it you could easily use **UPX**.  
3. First we need to unpack the file, next by searching Imorts we find some interesting ones like "CreateService", "InternetOpen", and "InternetOpenURL".


___

## <span style="color:#004F98;">**Lap 01-03:**</span>.
1. OMG, this one is familiar to more than 60 antiviruses on virustotal.![totalvirus](Images/3.png)
2. * first, using **peid** it tell us that it's an FSG 1.0 -> dulek/xt, after some search I knew that this is another way to pack a malware.![Alt text](Images/33.png)
   * second, using **peview** I didn't actually understand the sections names were empty and i didn't know what does this mean![Alt text](Images/3333.png)
   * third, I used **IDA Framework** to make sure, It is obvious now that this malware is packed.![IDA](Images/333.png)
   * forth, with some search I found that the process isn't just running an un-pack command like with **upx**, it has some other complicated steps.
3. without unpacking the file we can't know for sure what imports hints tell us.
4. without unpacking the file we can't know for sure what if the *host* or *network-based* indicators could be used to identify this malware on infected machines.

___
## <span style="color:#004F98;">**Lap 01-04:**</span>.

1. As usuall in this chapter it has been caught as malicious software by 57 antiviruse. ![Alt text](Images/4.png)
2. According to **PEid** it's a microsoft visual C++ file.                                                                                                          
   ![Alt text](Images/44.png)
3. Using **PEview** it looks like it was compiled on 30/8/2019 .![Alt text](Images/444.png)

___
___