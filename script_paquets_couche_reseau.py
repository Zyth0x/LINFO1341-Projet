import pyshark 
import pandas as pd
import time
import matplotlib.pyplot as plt
import numpy as np
import random
import socket

file = ['Appel_simple/appel_simple.pcapng',
         'Appel_simple_+_fichier/appel_simple_fichier.pcapng',
         'Appel_simple_+_message/appel_simple_message.pcapng',
         'Appel_simple_+_partage_d_ecran/appel_simple_partage_ecran.pcapng',
         'Message/message.pcapng',
         'Appel_vidéo/appel_video.pcapng',
         'Appel_vidéo_+_fichier/appel_video_fichiers.pcapng',
         'Appel_vidéo_+_message/appel_video_message.pcapng',
         'Fichiers/fichiers.pcapng'
         ]

title = ['Appel simple', 'Appel simple + fichier', 'Appel simple + message', 'Appel simple + partage d\'écran', 'Message', 'Appel vidéo', 'Appel vidéo + fichier', 'Appel vidéo + message', 'Fichiers']


#------------------------------------------------------------- Couche réseau -------------------------------------------------------------

tech_travers_nat = []
address = {}
domain_name = {}
for f in file:
    # Open the capture file
    cap = pyshark.FileCapture(f)

    # Find the address where the packets are sent
    for packet in cap:
        if packet.layers[1].layer_name.__contains__('ip') == False:
            print("Not an IP packet: " + packet.layers[1].layer_name)
            continue
        if address.keys().__contains__(packet.layers[1].dst) == False:
            address[packet.layers[1].dst] = 1
        else:
            address[packet.layers[1].dst] += 1
    
        
    

    cap._display_filter = 'ip'
    tech_nat = {"STUN": 0, "TURN": 0, "Teredo": 0, "UPnP": 0}
    for packet in cap:
        if packet.layers[-1].layer_name == 'stun':
            tech_nat['STUN'] = tech_nat.get('STUN', 0) + 1
        elif packet.layers[-1].layer_name == 'turn':
            tech_nat['TURN'] = tech_nat.get('TURN', 0) + 1
        elif packet.layers[-1].layer_name == 'teredo':
            tech_nat['Teredo'] = tech_nat.get('Teredo', 0) + 1
        elif packet.layers[-1].layer_name == 'upnp':
            tech_nat['UPnP'] = tech_nat.get('UPnP', 0) + 1

    tech_travers_nat.append((file.index(f), tech_nat))
    cap.close()

for addr in address:
    try:
        domain_name[addr] = socket.gethostbyaddr(addr)[0]
    except:
        pass



#------------------------------------------------------------- Graphes -------------------------------------------------------------

# Graphe qui prend en abscisse les fichiers et en ordonnée le nombre de paquets de chaque type de NAT et affiche des barres pour chaque type de NAT pour chaque fichier avec matplotlib
fig, ax = plt.subplots()
index = np.arange(len(tech_travers_nat[0][1]))
bar_width = 0.8 / len(file) # modification de la largeur des barres
opacity = 0.8

for i in range(len(tech_travers_nat)):
    ax.bar(index + i*bar_width, tech_travers_nat[i][1].values(), bar_width, alpha=opacity, label=title[i])

ax.set_xlabel('Types de NAT')
ax.set_ylabel('Nombre de paquets')
ax.set_title('Nombre de paquets de chaque type de NAT')
ax.set_xticks(index + bar_width*len(title)/2 - bar_width/2) # centrage des ticks
ax.set_xticklabels(tech_travers_nat[0][1].keys())
ax.legend()

fig.tight_layout()
#plt.savefig('Couche_reseau/graph_nat.pdf')


# Graphe pour faire les addresses IP
colors = []
labels_pct = []
for i in range(114):
    # Générer une couleur aléatoire
    color = tuple(random.uniform(0, 1) for _ in range(4))
    
    # Ajouter la couleur à la liste
    colors.append(color)

total_freq = sum(address.values())
sizes = list(address.values())
labels = list(address.keys())
percentages = [100 * (freq/total_freq) for freq in sizes]

for i, pct in enumerate(percentages):
    if pct >= 2:
        labels_pct.append(labels[i])
    else:
        labels_pct.append('')


# Créer un graphique camembert
fig, ax = plt.subplots()
ax.pie(sizes, labels=labels_pct, autopct=lambda pct: f"{pct:.1f}%" if pct >= 2 else '', startangle=90, colors=colors)
ax.axis('equal')
plt.title('Fréquence des adresses IP')
#plt.savefig('Couche_reseau/graph_address_ip.pdf')






