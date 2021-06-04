import os
import re

filePath = __file__
directory = os.path.dirname(filePath) + "/Trame/"               # permet de récupérer le dossier de la trame où qu'il soit
print("Si pas de réponse, la trame analysée sera 'trame.txt'")

while(True):
    name = input("Quel est le nom du fichier à analyser (inclure .txt) : ") or "trame.txt"                              # on demande le nom du fichier contenant les trames, si on appuie sur entrée directement, on prend trame.txt
    try:
        fich = open(directory + name, "r")
        break 
    except(FileNotFoundError):
        print("The requested file does not exist.\n")   

cont = fich.read().split("\n")                                  # on ouvre le fichier texte, on le lit en entier dans une chaine, on split la chaine en fonction de \n
fich.close()

fich2=[]
rep=[]
m=[]
z=0

Type={
    '0805':'X.25 niveau 3',
    '0806':'ARP',
    '8035':'RARP',
    '8098':'Appletalk'
}

Protocol={
    '01':'ICMP',
    '02':'IGMP',
    '06':'TCP',
    '08':'EGP',
    '09':'IGP',
    '11':'UDP',
    '24':'XTP',
    '46':'RSVP'
}

optionIP={
    '00':'End of Options List(EOOL)',
    '01':'No Operation(NOP)',
    '07':'Record Route(RR)',
    '44':'Time Stamp(TS)',
    '83':'Loose Source Route(LSR)',
    '89':'Strict Source Route(SSR)'
}

optionTCP={
    '00':'End of Options List(EOOL)',
    '01':'No Operation(NOP)',
    '02':'Maximum Segment Size(MSS)',
    '03':'Windows Scale WSopt',
    '08':'Time Stamp(TS)'
}

requestHTTP={
    '474554' : 'GET',
    '48454144' : 'HEAD',
    '504f5354' : 'POST',
    '505554' : 'PUT',
    '44454c455445' : 'DELETE'
}


#####################################################
# Fonctions de traitement des différents protocoles #
#####################################################


def UDP(i):
    if len(Dict[i]) >= opLast + 8:                                                                              # On vérifie que l'entête UDP soit complète
        print("*UDP :")
        res.write("*UDP :\n")
        sPort = Dict[i][opLast+1] + Dict[i][opLast+2]                                                           # On extrait le numéro de port source
        print("---------------> Source Port : " + str(int("0x"+sPort, 16)))
        res.write("---------------> Source Port : " + str(int("0x"+sPort, 16)) + "\n")
        dstPort = Dict[i][opLast+3] + Dict[i][opLast+4]                                                         # On extrait le numéro de port destination
        print("---------------> Destination Port : " + str(int("0x"+dstPort, 16)))
        res.write("---------------> Destination Port : " + str(int("0x"+dstPort, 16)) + "\n")
        lenUDP = Dict[i][opLast+5] + Dict[i][opLast+6]                                                          # On extrait le champ Length de UDP
        print("---------------> Length : " + str(int("0x"+lenUDP, 16)))
        res.write("---------------> Length : " + str(int("0x"+lenUDP, 16)) + "\n")
        checksum = Dict[i][opLast+7] + Dict[i][opLast+8]                                                        # On extrait le champs Checksum
        print("---------------> Checksum : " + str(int("0x"+checksum, 16)) + " [unverified]")
        res.write("---------------> Checksum : " + str(int("0x"+checksum, 16)) + " [unverified]\n")
        return 0, opLast + 9, int("0x"+dstPort, 16), int("0x"+sPort, 16)
    else:
        return 1, 0, 0, 0                                                                                       # Si l'entête UDP est incomplète on renvoie le code d'erreur 1
    

def TCP(i):
    if len(Dict[i]) >= opLast + 20:                                                                             # Si la partie fixe de l'entête TCP est complète
        print("*TCP :")
        res.write("*TCP :\n")
        sPort = Dict[i][opLast+1] + Dict[i][opLast+2]                                                           # On extrait le numéro de port source
        print("---------------> Source Port : " + str(int("0x"+sPort, 16)))
        res.write("---------------> Source Port : " + str(int("0x"+sPort, 16)) + "\n")
        dstPort = Dict[i][opLast+3] + Dict[i][opLast+4]                                                         # On extrait le numéro de port destination
        print("---------------> Destination Port : " + str(int("0x"+dstPort, 16)))
        res.write("---------------> Destination Port : " + str(int("0x"+dstPort, 16)) + "\n")
        SN = Dict[i][opLast+5] + Dict[i][opLast+6] + Dict[i][opLast+7] + Dict[i][opLast+8]                      # On extrait le Sequence Number
        print("---------------> Sequence number : 0x" + SN + " (" + str(int("0x"+SN, 16)) + ")")
        res.write("---------------> Sequence number : 0x" + SN + " (" + str(int("0x"+SN, 16)) + ")\n")
        AN = Dict[i][opLast+9] + Dict[i][opLast+10] + Dict[i][opLast+11] + Dict[i][opLast+12]                   # On extrait le Acknowledgment Number
        print("---------------> Acknowledgment number : 0x" + AN + " (" + str(int("0x"+AN, 16)) + ")")
        res.write("---------------> Acknowledgment number : 0x" + AN + " (" + str(int("0x"+AN, 16)) + ")\n")
        dataOff = Dict[i][opLast+13][0]                                                                         # On extrait le champs Data Offset
        print("---------------> TCP Header length : " + str(int("0x"+dataOff, 16)*4) + " bytes")
        res.write("---------------> TCP Header length : " + str(int("0x"+dataOff, 16)*4) + " bytes\n")
    
        reserved = bin(int(Dict[i][opLast+13][1],16))[2:].zfill(4)+ bin(int(Dict[i][opLast+14][0],16))[2:].zfill(4)[:2]                  # On extrait les 6 bits du champs Reserved
        print("---------------> Reserved : " + reserved)
        res.write("---------------> Reserved : " + reserved + "\n")
    
        print("---------------> Flags :")
        res.write("---------------> Flags :\n")
    
        flag = bin(int(Dict[i][opLast+14][0],16))[2:].zfill(4)[2:] + bin(int(Dict[i][opLast+14][1],16))[2:].zfill(4)                     # On extrait les 6 bits des flags
    
        if flag[0] == '1':
            print("                   Urgent : Set")
            res.write("                   Urgent : Set\n")
        else:
            print("                   Urgent : Not Set")
            res.write("                   Urgent : Not Set\n")
        if flag[1] == '1':
            print("                   Acknowledgment : Set")
            res.write("                   Acknowledgment : Set\n")
        else:
            print("                   Acknowledgment : Not Set")
            res.write("                   Acknowledgment : Not Set\n")
        if flag[2] == '1':
            print("                   Push : Set")
            res.write("                   Push : Set\n")
        else:
            print("                   Push : Not Set")
            res.write("                   Push : Not Set\n")
        if flag[3] == '1':
            print("                   Reset : Set")
            res.write("                   Reset : Set\n")
        else:
            print("                   Reset : Not Set")
            res.write("                   Reset : Not Set\n")
        if flag[4] == '1':
            print("                   Syn : Set")
            res.write("                   Syn : Set\n")
        else:
            print("                   Syn : Not Set")
            res.write("                   Syn : Not Set\n")
        if flag[5] == '1':
            print("                   Fin : Set")
            res.write("                   Fin : Set\n")
        else:
            print("                   Fin : Not Set")
            res.write("                   Fin : Not Set\n")

        window = Dict[i][opLast+15] + Dict[i][opLast+16]                                                        # On extrait le champs Window 
        print("---------------> Window : " + str(int("0x"+window, 16)))
        res.write("---------------> Window : " + str(int("0x"+window, 16)) + "\n")
        checksum = Dict[i][opLast+17] + Dict[i][opLast+18]                                                      # On extrait le champs Checksum
        print("---------------> Checksum : " + str(int("0x"+checksum, 16)) + " [unverified]")
        res.write("---------------> Checksum : " + str(int("0x"+checksum, 16)) + " [unverified]\n")

        # Options TCP :
        if (int(dataOff, 16) > 5):
            if len(Dict[i]) >= opLast + int(dataOff, 16)*4:
                print("---------------> TCP Options :")                                                             # Si on sait qu'il y a des options...
                res.write("---------------> TCP Options :\n")
                n = opLast + 21                                                                                     # On se place sur le premier le premier octet des options
                while (n <= (opLast+int(dataOff, 16)*4) and Dict[i][n] != '00'):                                    # Tant que l'octet courant n'est l'octet de fin d'options, et qu'on est encore dans l'espace des options
                    if Dict[i][n] == '01':                                                                          # Si c'est une option NOP on passe à l'octet suivant
                        print("                   > Option NOP")
                        res.write("                   > Option NOP\n")
                        n += 1
                        continue
                    try:
                        opt = optionTCP[Dict[i][n]]                                                                         # Sinon, on prend l'octet du type d'option et on détermine l'option présente
                    except KeyError:
                        print("                   > Unknown option")
                        res.write("                   > Unknown option")
                        optLen = Dict[i][n+1]                                                                                   # On récupère la longueur totale de l'option
                        n += int(optLen, 16)                                                                                    # On se place au prochain octet après l'option
                        continue
               
                        # Option MSS 
                    if opt == 'Maximum Segment Size(MSS)':
                        print("                   > Maximum Segment Size :")
                        res.write("                   > Maximum Segment Size :\n")
                        print("                       MSS = " + str(int(Dict[i][n+2]+Dict[i][n+3], 16)) + " bytes")            # On extrait la valeur du MSS
                        res.write("                       MSS = " + str(int(Dict[i][n+2]+Dict[i][n+3], 16)) + " bytes\n")
                        n += 4                                                                                                 # On se place au prochain octet après l'option
                        continue
                        # Option Window Scale
                    if opt == 'Windows Scale WSopt':
                        print("                   > Windows Scale WSopt :")
                        res.write("                   > Windows Scale WSopt :\n")
                        print("                       Shift = " + str(int(Dict[i][n+2], 16)))                                  # On extrait la valeur du Shift
                        res.write("                       Shift = " + str(int(Dict[i][n+2], 16)) + "\n")
                        n += 3                                                                                                 # On se place au prochain octet après l'option
                        continue
                        # Option Time Stamp
                    if opt == 'Time Stamp(TS)':
                        tsVal = "0x" + Dict[i][n+2] + Dict[i][n+3] + Dict[i][n+4] + Dict[i][n+5]                                # On extrait le Time Stamp Value
                        terVal = "Ox" + Dict[i][n+6] + Dict[i][n+7] + Dict[i][n+8] + Dict[i][n+9]                               # On extrait le Time Echo Reply Value
                        print("                   > Time Stamp :")
                        res.write("                   > Time Stamp :\n")
                        print("                       Time Stamp Value : " + tsVal)
                        res.write("                       Time Stamp Value : " + tsVal + "\n")
                        print("                       Time Echo Reply Value : " + terVal)
                        res.write("                       Time Echo Reply Value : " + terVal + "\n")
                        n += 10                                                                                                 # On se place au prochain octet après l'option
                        continue
            else:
                return 2, 0, 0, 0, 0                                                                                        # Si la partie options de l'entête est incomplète, on renvoie le code d'erreur 2
            return 0, n, int("0x"+dstPort, 16), int("0x"+sPort, 16), dataOff
        return 0, opLast + 20, int("0x"+dstPort, 16), int("0x"+sPort, 16), dataOff
    else:                                                                                                                   # Si la partie fixe est incomplète on renvoie le code d'erreur 1
        return 1, 0, 0, 0, 0


def HTTP(i, n):
    print("*HTTP :")
    res.write("*HTTP :\n")
    s = ""
    if portSrc != 80:  # On va vérifier qu'on a bien une requête du client, si ce sont juste des données on ne les affichera pas
        s += Dict[i][n] + Dict[i][n+1] + Dict[i][n+2]
        if not(s in requestHTTP):
            s += Dict[i][n+3]
            if not(s in requestHTTP):
                s += Dict[i][n+4][n+5]
                if not(s in requestHTTP):
                    print("   Only data.")
                    res.write("   Only data.\n")
                    return
    
    else:  # On vérifie sinon qu'on a bien un message de réponse (qui commence par HTTP) du serveur et pas seulement des données quelconques
        s += Dict[i][n] + Dict[i][n+1] + Dict[i][n+2] + Dict[i][n+3]
        if s != '48545450':
            print("   Only Data.")
            res.write("   Only Data.\n")
            return

    s = ""
    while Dict[i][n] != '0d' or Dict[i][n+1] != '0a' or Dict[i][n+2] != '0d' or Dict[i][n+3] != '0a':
        if Dict[i][n] == '0d' and Dict[i][n+1] == '0a':
            b=bytes.fromhex(s)
            d=b.decode("ASCII")
            print(d)
            res.write(d + "\n")
            n += 2
            s = ""
        s += Dict[i][n]
        n += 1


def IP(i):
    if len(Dict[i]) >= 34:                                                                              # Si la partie statique de l'entête IP est complète
        print("----> Type : 0x"+str(typepro)+" (IPv4)")
        res.write("----> Type : 0x"+str(typepro)+" (IPv4)\n")
        print("*IP :")
        res.write("*IP :\n")
        version = Dict[i][14][0]                                                                        # on extrait la valeur du champs Type
        print("--------> Version : "+version)
        res.write("--------> Version : " + version + "\n")
        head =int('0x'+Dict[i][14][1],16)*4                                                             # on extrait la longueur de l'entête IP (en nombre d'octets)
        print("--------> Header length : "+str(head)+" bytes")
        res.write("--------> Header length : "+str(head)+" bytes\n")
        total=Dict[i][16]+Dict[i][17]                                                                   # on extrait le champs Total Length
        total=int('0x'+total,16)
        print("--------> Total Size (Header + data): "+str(total) + " bytes")
        res.write("--------> Total Size (Header + data): "+str(total) + " bytes\n")
        id=Dict[i][18]+Dict[i][19]                                                                      # Champ identifiant du message
        print("--------> Identification: 0x"+id+" ("+str(int('0x'+id,16))+")")
        res.write("--------> Identification: 0x"+id+" ("+str(int('0x'+id,16))+")\n")
        flag=bin(int(Dict[i][20][0],16))[2:].zfill(4)                                                   # On extrait les flags
       
        print("--------> Flags :")
        res.write("--------> Flags :\n")
        if flag[2]=='1':
            DF='Don\'t fragment : Set '
        else: 
            DF='Don\'t fragment : Not set '
        if flag[1]=='1':
            MF='More fragments : Set'
        else:    
            MF='More fragments : Not set'
        if flag[0]=='1':
            reserved='Reserved bit : Set'
        else:
            reserved='Reserved bit: Not set'
        offset=flag[3]+Dict[i][20][1]+Dict[i][21]                                                       # On extrait le champ Fagment Offset
        print("            "+reserved)
        res.write("            "+reserved + "\n")
        print("            "+MF)
        res.write("            "+MF+ "\n")
        print("            "+DF)
        res.write("            "+DF+ "\n")
            
        print("--------> Fragment offset : "+offset)
        res.write("--------> Fragment offset : "+offset+ "\n")
        ttl=str(int(Dict[i][22],16))                                                                    # On extrait le champ TTL
        print("--------> Time to live : "+ttl)
        res.write("--------> Time to live : "+ttl+ "\n")
        prtc=Dict[i][23]                                                                                # On extrait le champ protocole
            
        if prtc in Protocol.keys():                                                                     # Si c'est un protocole qu'on reconnaît...
            prtc=Protocol[prtc]                                                                         # On récupère la valeur associée à la clé du protocole
        else:
            prtc="Unknown protocol"
        print("--------> Protocol : "+prtc)
        res.write("--------> Protocol : "+prtc+ "\n")
        chek='0x'+Dict[i][24]+Dict[i][25]+" [Unverified] "                                              # On extrait le champs Checksum
        print("--------> Header checksum : "+chek)
        res.write("--------> Header checksum : "+chek+"\n")
            
        src=str(int(Dict[i][26],16))+'.'+str(int(Dict[i][27],16))+'.'+str(int(Dict[i][28],16))+'.'+str(int(Dict[i][29],16))          # On extrait le champs IP source
        dst=str(int(Dict[i][30],16))+'.'+str(int(Dict[i][31],16))+'.'+str(int(Dict[i][32],16))+'.'+str(int(Dict[i][33],16))          # On extrait le champs IP destination
        print("--------> IP source adress : "+src)
        res.write("--------> IP source adress : " + src + "\n")
        print("--------> IP destination adress : "+dst)
        res.write("--------> IP destination adress : " + dst + "\n")
                
        if head > 20:
            if len(Dict[i]) >= 34 + (head - 20):                                                         # Si les données des options sont complètes
                # Options IP
                n=34
                while Dict[i][n]!='00' and n<=33+head-20:
                    if Dict[i][n]=='01':
                        print("> Option NOP")
                        res.write(" > Option NOP\n")
                        n=n+1
                    else:
                        opt=optionIP[Dict[i][n]]
                        n=n+1
                        optlen=str(int(Dict[i][n],16))
                        n=n+1
                        val=int(Dict[i][34],16)
                        n=n+1
                        print("          > Ip option : "+opt)
                        res.write("          > Ip option : "+opt + "\n")
                        print("          > length: "+optlen+' octets')
                        res.write("          > length: "+optlen+' octets\n')
                        m=int(optlen)-3+n
                        if opt!='Time Stamp(TS)':
                            while n<m:
                                if n+3<m:
                                    rot=str(int(Dict[i][n],16))+'.'+str(int(Dict[i][n+1],16))+'.'+str(int(Dict[i][n+2],16))+'.'+str(int(Dict[i][n+3],16))
                                    print("   Ip Router ->"+rot)
                                    res.write("   Ip Router ->"+rot + "\n")
                                    n=n+4
                                else:
                                    break
                        else:
                            while n<m:
                                if n+3<m:
                                    rot=str(int(Dict[i][n],16))+str(int(Dict[i][n+1],16))+str(int(Dict[i][n+2],16))+str(int(Dict[i][n+3],16))
                                    print("Timestamp ->"+rot)
                                    res.write("Timestamp ->"+rot + "\n")
                                    n=n+4
                                else:
                                    break
            
            else:                                                     # Si la trame est incomplète au niveau des options, on renvoie le code d'erreur 2
                return 2, 0, 0, 0
        else:
            print("--------> No options")
            res.write("--------> No options\n")
        return 0, head, total, prtc                                     
    
    else:                                                              # Si la trame est incomplète au niveau de la partie fixe on renvoie le code d'erreur 1
        return 1, 0, 0, 0




########################################################
# Traitement du fichier texte et extraction des trames #
########################################################

# cont[i] correspond à la i-ème ligne du fichier
trame_regex = re.compile(r'^(?P<off>[a-f0-9]{2,})(?:[ ]+)(?P<fr>([a-f0-9]{2}[ ])*)')   # On retient uniquement les offsets et les octets de la trame, les chaînes de caractères sont ignorées
for i in range(0,len(cont)):
    j=trame_regex.match(cont[i].lower())                                   # j contient les matchs de la regex
           
    if j :                                                                 # si la regex a renvoyé quelque chose
        jOff = j.groupdict()["off"]                                        # Le groupe contenant l'offset
        jFr = j.groupdict()["fr"].split(" ")                               # Le groupe contenant les octets
        jFr.insert(0, jOff)                                                # On reconstitue la ligne avec son offset
        if len(jFr[-1]) == 0:                                              # On supprime le dernier élément vide issu du split (ligne 187)
                jFr.pop()                                            
            
        fich2.append(jFr)                                                  # fich2 contient le contenu de cont filtré




somme = 0                                                                  # contenir le nombre d'octets déjà lus pour vérifier l'offset
Dict={}                                                                    # dictionnaire dont chaque entrée correspond à une trame et contient les données de cette trame
nom="Frame "                                                               # utile pour le nom de la trame
index =1                                                                   # contient le numéro de la trame courante
z = 0
i=0
while i<len(fich2):                                                        # Tant qu'il y a des lignes à étudier...   
    if int('0x'+fich2[i][0],16)==0:                                        # si l'offset est égal à 0, on va créer une nouvelle trame
        numero_trame=nom+str(index)                                        # on crée la clé correspondant à la trame pour le dico
        Dict[numero_trame]=[]                                              # on ajoute l'entrée au dico
        index=index+1                                                      # on augmente le nombre de trames de 1
        somme=0                                                            # on remet le compteur des octets à 0
        for j in range(1,len(fich2[i])):                                   # on calcule le nombre d'octets de la ligne
            somme=somme+1
            Dict[numero_trame].append(fich2[i][j])                         # on rajoute progressivement les octets à l'entrée du dictionnaire
        i=i+1
    else:
        if int('0x'+fich2[i][0],16)==somme:                                # si ce n'est pas le début d'une trame, on vérifie la validité de l'offset
            for j in range(1,len(fich2[i])):                               # on calcule le nombre d'octets de la ligne
                somme=somme+1
                Dict[numero_trame].append(fich2[i][j])                     # on rajoute progressivement les octets à l'entrée du dictionnaire
            i=i+1
        else:
            print(numero_trame  + " invalid : offset error : " + '0x' + fich2[i][0])
            print(fich2[i-1])                                              # affiche la ligne où a eu lieu l'erreur
            Dict[numero_trame]=[]                                          # si l'offset n'est pas valide, on met l'entrée du dico vide
            while i < len(fich2) and int('0x'+fich2[i][0],16)!=0: # puis on cherche la prochaine trame
                i=i+1
            

################################################################################
# Analyse des trames extraites et écriture des résultats dans un fichier texte #
################################################################################

directory = os.path.dirname(filePath) + "/Resultats/"
name = input("Quel est le nom du fichier où sauvegarder le résultat (par défaut 'resultats.txt') : ") or "resultats.txt"
res = open(directory + name, "w")  # on crée le fichier de résultats avec le nom spécifié

for i in Dict.keys():                                                      # pour chaque trame dans le dico...
    if len(Dict[i]) !=0:                                                   # si la trame est valide                                                         
        print("\n" + i)                                                    # Afficher le nom de la trame
        if i != 'Frame 1':
            res.write("\n\n" + i + "\n")
        else:
            res.write(i + "\n")                                            # L'écrire dans le fichier
        # Début de l'analyse Ethernet
        if len(Dict[i]) > 14 :                                             # si l'en-tête Ethernet est complète
            print("*Ethernet 2 :")
            res.write("*Ethernet 2 :\n")                                                 
            dest=Dict[i][0]+':'+Dict[i][1]+':'+Dict[i][2]+':'+Dict[i][3]+':'+Dict[i][4]+':'+Dict[i][5]                                  # on extrait les 6 octets de l'adresse MAC destination
            print("----> MAC destination address : "+dest)
            res.write("----> MAC destination address : "+ dest + "\n")
            src=Dict[i][6]+':'+Dict[i][7]+':'+Dict[i][8]+':'+Dict[i][9]+':'+Dict[i][10]+':'+Dict[i][11]                                 # on extrait les 6 octets de l'adresse MAC source
            print("----> MAC source address : "+src)
            res.write("----> MAC source address : " + src + "\n")
            typepro=Dict[i][12]+Dict[i][13]                                                                                             # on extrait la valeur du champs Type
            
            
            if typepro=="0800" :
                # Début analyse IP
                valid, head, total, prtc = IP(i)
                if valid == 1:                                                                                                           # Si l'entête IP n'est pas complète, on affiche le message d'erreur et on passe à la trame suivante
                    print("Error in " + i + ". IP  header not complete (in its fix part).")
                    res.write("Error in " + i + ". IP  header not complete (in its fix part).\n")
                    Dict[i] = []
                    continue
                if valid == 2:
                    print("Error in " + i + ". IP  header not complete (in its option part).")
                    res.write("Error in " + i + ". IP  header not complete (in its option part).\n")
                    Dict[i] = []
                    continue
                
                opLast=33+head-20
                if prtc=='TCP':
                    valid, n, portDest, portSrc, dataOff = TCP(i)
                    if valid == 1:
                        print("Error in " + i + ". TCP  header not complete (in its fix part).")
                        res.write("Error in " + i + ". TCP  header not complete (in its fix part).\n")
                        Dict[i] = []
                        continue
                    if valid == 2:
                        print("Error in " + i + ". TCP  header not complete (in its option part).")
                        res.write("Error in " + i + ". TCP  header not complete (in its option part).\n")
                        Dict[i] = []
                        continue
                    
                elif prtc=='UDP':
                    valid, n, portDest, portSrc = UDP(i)
                    if valid == 1:
                        print("Error in " + i + ". UDP header not complete.")
                        res.write("Error in " + i + ". UDP header not complete.\n")
                        Dict[i] = []
                        continue
                    
                if n < total and (portDest == 80 or portSrc == 80):  # s'il y a des données applicatives et si le port source ou destination est 80...
                    if len(Dict[i]) - 14 < total:  # si les données de http sont incomplètes, on renvoie un message d'erreur et on n'analyse pas ces données
                        print("Error in " + i + ". HTTP data not complete.")    # On s'assure que les données HTTP sont complètes
                        res.write("Error in " + i + ". HTTP data not complete.\n")
                        continue
                    if len(Dict[i]) - 14 > total:
                        print("Error in " + i + ". HTTP data has more bytes than it should.")
                        res.write("Error in " + i + ". HTTP data has more bytes than it should.\n")
                        continue
                    HTTP(i, n)

            else:
                if typepro in Type.keys():
                    print("Champ Ethernet Type : 0x"+str(typepro)+" "+Type[typepro])               # On affiche simplement le protocole reconnu sans l'analyser
                    res.write("Champ Ethernet Type : 0x"+str(typepro)+" "+Type[typepro] + "\n")
        else:
            print("Error in " + i + ". Ethernet header not complete.")                             # Si l'entête Ethernet est incomplète, on affiche le message d'erreur et on passe à la trame suivante
            res.write("Error in " + i + ". Ethernet header not complete.\n")
            Dict[i] = []
            continue

res.close()
os.system("pause")