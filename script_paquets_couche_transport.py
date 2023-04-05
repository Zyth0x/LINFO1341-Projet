import pyshark
import pandas as pd
import time
import matplotlib.pyplot as plt

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

#------------------------------------------------------------- Couche transport -------------------------------------------------------------

exist_protocol = ["tcp","DATA","sctp","dccp","rsvp","spx","tp0-tp4","mptcp","quic","pgm","ltp","atmp","il","rudp","ipx","gtp","enrp","tipc","beet","hudp","kcp","wsp","sctp/rsvp"]

protocols = []

protocols_with_udp = []
for f in file:
    # Open the capture file
    cap = pyshark.FileCapture(f)

    prot = {}
    prot_with_udp = {}

    for packet in cap:
        if packet.layers[-1].layer_name in exist_protocol:
            if prot.keys().__contains__(packet.layers[-1].layer_name) == False:
                prot[packet.layers[-1].layer_name] = 1
            else:
                prot[packet.layers[-1].layer_name] += 1
        
        if len(packet.layers) > 3:
            if packet.layers[2].layer_name == 'udp':
                if prot_with_udp.keys().__contains__(packet.layers[-1].layer_name) == False:
                    prot_with_udp[packet.layers[-1].layer_name] = 1
                else:
                    prot_with_udp[packet.layers[-1].layer_name] += 1
            
    
    prot['udp'] = prot['DATA']
    prot.pop('DATA')
    protocols.append((file.index(f), prot))
    protocols_with_udp.append((file.index(f), prot_with_udp))

    # Graphe des protocoles utilisés en camembert en pourcentage avec matplotlib
    nmb_total = sum(prot.values())
    labels = list(prot.keys())
    sizes = [prot[k] / nmb_total for k in labels]
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90)
    ax.axis('equal')
    plt.title(title[file.index(f)])
    #plt.savefig('Couche_transport/graph_transport_protocols_for_' + title[file.index(f)] + '.pdf')

print(protocols_with_udp)