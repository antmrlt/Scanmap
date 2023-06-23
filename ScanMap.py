#!/usr/bin/python3

import os
from progress.bar import Bar
import re
import xml.etree.ElementTree as ET
import pyfiglet

#### Fonction qui recupere l'ip et l'os dans le xml ###

def parse_nmap_xml(file):
	tree = ET.parse(file)
	root = tree.getroot()

	result = []

	for host in root.iter('host'):
		address = host.find('address').get('addr')
		host_info = {
			'address': address
		}

		os_element = host.find('.//os')

		if os_element is not None:
			osmatch = os_element.find('.//osmatch')
			if osmatch is not None:
				os_name = osmatch.get('name')
				os_accuracy = osmatch.get('accuracy')

				host_info['os_name'] = os_name
				host_info['os_accuracy'] = os_accuracy

		result.append(host_info)
	return result

### Fonction qui genere et ecrit le csv ###

def csvwrite(xml_name):

	t = []

	xml_p = parse_nmap_xml(xml_name)

	for i in range(len(xml_p)):
		a = xml_p[i]
		valeurs = list(a.values())
		t.append(valeurs)

	sortie = []
	csv_file = "bilan_" + date + "_" + heureminute + ".csv"

	if csv_file not in os.popen("ls", "r").read():
		os.system("touch " + date + "/" + csv_file)

	#empty = os.popen("cat " + date + "/" + csv_file, "r").readlines() >-> en cas d'ajout et non de suppression au fichier csv

	ligne = os.popen("cat grep.txt").readlines()

	for i in range(len(ligne)):

		ip_match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', ligne[i])

		if ip_match:
			ip = ip_match.group(1)

		p_match = re.findall(r'(\d+)/(\w+)/tcp//(\w+)', ligne[i])

		for port, state, protocol in p_match:
			sub = [ip, port, state, protocol]
			sortie.append(sub)

	dict1 = {}

	for sublist in t:
		ip = sublist[0]
		if ip in dict1:
		        dict1[ip].append(sublist[1:])
		else:
		        dict1[ip] = [sublist[1:]]

	result = []

	for sublist in sortie:
		ip = sublist[0]
		if ip in dict1:
		        joined_sublist = sublist + dict1[ip]
		        result.append(joined_sublist)
		        
	with open(date + '/' + csv_file, 'a') as f:
		if os.popen("cat " + date + "/" + csv_file, "r").read() == "":
			f.write("IP;STATE;PORT;PROTOCOLE;OS;ACCURACY OS\n")
		for i in range(len(result)):
			if result[i][4] == []:
				f.write(result[i][0] + ";" + result[i][2] + ";" + result[i][1] + ";" + result[i][3] + "%\n")
			else:
				f.write(result[i][0] + ";" + result[i][2] + ";" + result[i][1] + ";" + result[i][3] + ";" + result[i][4][0] + ";" + result[i][4][1] + "%\n")
					### IP ###	     ### State ###	  ### Port ###        ### Protocol ###       ### OS ###         ### Accuracy os ###

### Fonction qui récupere le 3eme bit###

def thirdB(adresses):
	thirdBits = []
	for adresse in adresses:
		adresse_split = adresse.split('.')
		thirdBit = adresse_split[2]
		thirdBits.append(thirdBit)
	return thirdBits

### Fonction qui récupere les deux premiers bits###

def ext2pb(adresses):
	dpbs = []
	for adresse in adresses:
		adresse_split = adresse.rsplit(".", 2)
		dpb = adresse_split[0]
		dpbs.append(dpb)
	return dpbs

def detail():
	for i in range(len(lines)):
		percent = ((i+1)/len(lines))*100
		print("[+]", end="")
		print(percent, end="")
		print("% | Scan " + lines[i] + "/24 : ", end="")

		if (thirdBits[i] + ".html") in os.popen("ls " + date + "/" +dpbs[i] + ".X.X").read():
			os.system("rm " + date + "/" + dpbs[i]  + ".X.X/" + thirdBits[i] + ".html") ### Supprime le fichier de scan précédent pour le remplacer

		os.system("sudo nmap --top-ports 250 -n -O " + lines[i] + "/24 --min-rate 1000 -oG grep.txt -oX " + thirdBits[i] + ".xml > /dev/null") # Scan Nmap avec sortie XML

		xml_name = thirdBits[i] + ".xml"

		if csv == 1:
			csvwrite(xml_name)

		f = open(thirdBits[i] + ".xml")
		l = f.readlines()[-1]

		if l == "</nmaprun>\n": ### Check si le fichier xml est complet
			print("OK")
			os.system("Xalan -a " + thirdBits[i] + ".xml -o " + thirdBits[i] + ".html >> " + date + "/" + dpbs[i] + ".X.X/" + thirdBits[i]  + ".html") # Conversion XML -> HTML
		else:
			print("Un problème est survenue")

		os.system("sudo rm " + thirdBits[i] + ".xml") # suppression des fichiers xml

def pourcent():
	bar = Bar('Processing', fill='█', max=len(lines))

	print("\n")

	for i in range(len(lines)):

		xml_name = thirdBits[i] + ".xml"

		if (thirdBits[i] + ".html") in os.popen("ls " + date + "/" + dpbs[i] + ".X.X").read():
			os.system("rm " + date + "/" + dpbs[i]  + ".X.X/" + thirdBits[i] + ".html 2> /dev/null") ### Supprime le fichier de scan précédent pour le remplacer

		os.system("sudo nmap --top-ports 250 -n -O " + lines[i] + "/24 --min-rate 1000 -oG grep.txt -oX " + xml_name + " > /dev/null") # Scan Nmap avec sortie XML

		if csv == 1:
			csvwrite(xml_name)

		f = open(thirdBits[i] + ".xml")
		l = f.readlines()[-1]

		if l == "</nmaprun>\n": ### Check si le fichier xml est complet
			os.system("Xalan -a " + xml_name + " -o " + thirdBits[i] + ".html >> " + date + "/" + dpbs[i] + ".X.X/" + thirdBits[i]  + ".html") # Conversion XML -> HTML

		os.system("sudo rm " + thirdBits[i] + ".xml 2> /dev/null") # suppression des fichiers xml

		bar.next()

	bar.finish()

print(pyfiglet.figlet_format('@ScanMap@'))

date = os.popen('date +"%Y%m%d"', "r").read() #Determine la date pour dater le scan
date = date.rstrip('\n')

heureminute = os.popen('date +"%H%M"', "r").read()
heureminute = heureminute.rstrip('\n')

if 'grep.txt' in os.popen("ls", "r").read():
	os.system('rm grep.txt')
	
create = 0

if date not in os.popen("ls", "r").read():
	os.system('mkdir ' + date) #Crée un dossier pour la date du jour si premier scan
	create = 1

print("[+]Rentrez le nom du fichier text contenant les sous réseaux à scanner (sans le .txt)  : ", end="")
entre = input()
entre2 = entre + ".txt"

if entre2 not in os.popen("ls", "r").read(): #test si le fichier existe
	print("[+]Le fichier n'a pas été trouvé, annulation du programme")
	if create == 1:
		os.system("rm " + date)
else:
	file = open(entre2)
	lines = file.read().splitlines() # lis le fichier contenant les sous réseaux
	#print(lines) -> Afficher les sous réseaux contenu dans le fichier
	file.close()

	dpbs = ext2pb(lines)
	thirdBits = thirdB(lines)

	### Création d'une liste contenant les deux premier bit en fonction de la "forme" du sous réseau
	### Exemple : ['192.168', '10.10', '172.212']

	dicoLan = []
	dicoLan.append(dpbs[0])
	for i in range(len(lines)):
		for y in range(len(dicoLan)):
			if dpbs[i] not in dicoLan:
				dicoLan.append(dpbs[i])

	print("\n[+]Création des dossiers")

	for i in range(len(dicoLan)):
		if (dicoLan[i] + ".X.X") in os.popen("ls " + date, "r").read(): ### Check si le dossier existe deja
			print(" - Dossier deja existant")
		else:
			os.system("sudo mkdir " + date + "/" + dicoLan[i] + ".X.X 2> /dev/null") ### Si non il le crée
			print(" - Dossier " + dicoLan[i] + ".X.X crée")


	print("\n[+]Choisissez affichage détaillé ou progression (barre) (d ou p) : ", end="")
	rep = input()

	tent = 3

	for i in range(4):
		if rep != "d" and rep != "p":
			if i < 3:
				print("[+]Entrée non conforme, veillez réessayer (il vous reste " + str(tent) + " tentative) : ", end="")
				rep = input()
				tent = tent - 1
			else:
				print("[+]Annulation du programme")
				annulation = 1
		else:
			annulation = 0
			break
			
	if annulation != 1:
		print("\n[+]Souhaitez vous une sortie csv ? (o/n) : ", end="")
		csv = input()

		if csv == "o":
			csv = 1
		elif csv == "n":
			csv = 0
		else:
			print("[+]Entrée non conforme, aucun csv ne sera généré.\n") 


		### Choisir le mode d'affichage ###

		if rep == "d":
			detail()
		elif rep == "p":
			pourcent()

		os.system("rm grep.txt")

print("\n[+]Terminé")
