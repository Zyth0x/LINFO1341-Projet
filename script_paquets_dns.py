import pyshark 
import pandas as pd
import time
import matplotlib.pyplot as plt
import numpy as np
import dns.resolver


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

title = ['Appel\nsimple', 'Appel\nsimple\n+ fichier', 'Appel\nsimple\n+ message', 'Appel\nsimple\n+ partage\nd\'écran', 'Message', 'Appel\nvidéo', 'Appel\nvidéo\n+ fichier', 'Appel\nvidéo\n+ message', 'Fichiers']

#------------------------------------------------------------- DNS -------------------------------------------------------------

qry_type_name = {'1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA', '12': 'PTR', '15': 'MX', '16': 'TXT', '28': 'AAAA', '33': 'SRV', '255': 'ANY'}
num_of_request = []
prot = []
type_of_request = []
type_name_reqest = []
resolved_name = {}
for f in file:
    # Open the capture file
    cap = pyshark.FileCapture(f)
    
    start_time = float(cap[0].sniff_timestamp)

    data = []
    protocols = {}
    type_request = {"Iterative": 0, "Recursive": 0}

    for packet in cap:
        # Add the protocol name to the list or increment the counter
        if packet.layers[-1].layer_name in protocols:
            protocols[packet.layers[-1].layer_name] += 1
        else:
            protocols[packet.layers[-1].layer_name] = 1

        # Data for DNS
        if 'DNS' in packet:
            if (packet.dns.qry_name not in resolved_name):
                # Si le nom de domaine ne contient pas apple ou icloud dans son nom, alors on l'ajoute à la liste des noms de domaine résolus
                if ('apple' not in packet.dns.qry_name and 'icloud' not in packet.dns.qry_name and 'ucl' not in packet.dns.qry_name and 'uclouvain' not in packet.dns.qry_name):
                    resolved_name[packet.dns.qry_name] = 1
            else:
                resolved_name[packet.dns.qry_name] += 1


            if (packet.dns.flags_response == '0'):
                type = "Request"
            else:
                type = "Response"
                queries = [packet.dns.qry_name, qry_type_name.get(packet.dns.qry_type)]
                if ((file.index(f), packet.dns.qry_type,) not in type_name_reqest):
                    type_name_reqest.append((file.index(f), packet.dns.qry_type,))
                
                

            data.append({
                'response_time': float(packet.sniff_timestamp) - start_time,
                'type' : type,
            })

            # Type of request DNS
            if type == "Request":
                if packet.dns.flags_recdesired == '1':
                    type_request['Recursive'] = type_request.get('Recursive', 0) + 1
                else:
                    type_request['Iterative'] = type_request.get('Iterative', 0) + 1
    
    type_of_request.append((file.index(f), type_request))

        


        


    df = pd.DataFrame(data)


    protocols['udp'] = protocols['DATA']
    if '_ws.malformed' in protocols:
        protocols['malformed'] = protocols['_ws.malformed']
        protocols.pop('_ws.malformed')
    protocols.pop('DATA')


    protocols = {k: protocols[k] for k in sorted(protocols)}

    num_of_request.append((file.index(f), len(df[df['type'] == 'Request']), len(df[df['type'] == 'Response'])))
    prot.append((file.index(f), protocols))


    # Fais un graphique fromage avec les protocoles et leur pourcentage dedans avec matplotlib
    nmb_total = sum(protocols.values())
    labels = list(protocols.keys())
    sizes = [protocols[k] / nmb_total for k in labels]
    explode = [0.1 if sizes[i] > 0.05 else 0 for i in range(len(sizes))]
    threshold = 0.03 * nmb_total  # seuil de 3%
    # Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
    labels_filtered = [labels[i] if protocols[labels[i]] > threshold else '' for i in range(len(labels))]
    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 3 else '', shadow=False, startangle=90)
    ax1.axis('equal')
    plt.title(title[file.index(f)])
    #plt.savefig('DNS/graph_protocols_for_'+ title[file.index(f)] +'.pdf')
    

# Fais un graphique bar avec le nombre de requetes DNS de chaque fichier avec matplotlib
plt.figure()
plt.title("Nombre de requêtes DNS ")
#plt.xlabel("Fichier")
plt.ylabel("Nombre de requêtes")
plt.bar([title[i[0]] for i in num_of_request], [i[1] for i in num_of_request], label="Requêtes")
plt.xticks(fontsize=6)
plt.legend()
#plt.savefig('DNS/graph_num_of_request.pdf')

# Fais un graphique bar avec le type de requetes DNS de chaque fichier avec matplotlib
plt.figure()
plt.title("Type de requêtes DNS ")
#plt.xlabel("Fichier")
plt.ylabel("Nombre de requêtes")
plt.bar([title[i[0]] for i in type_of_request], [i[1]['Iterative'] for i in type_of_request], label="Itératives")
plt.bar([title[i[0]] for i in type_of_request], [i[1]['Recursive'] for i in type_of_request], bottom=[i[1]['Iterative'] for i in type_of_request], label="Récursives")
plt.xticks(fontsize=6)
plt.legend()
#plt.savefig('DNS/graph_type_of_request.pdf')


    

# Graphe camembert pour les noms d'entreprises
entreprise = {'Microsoft': 0, 'Akamai': 0}
for i in resolved_name:
    if ('teams' in i or 'skype' in i or 'office' in i or 'azure' in i or 'microsoftonline' in i or 'msidentity' in i or 'trafficmanager' in i or 'microsoft' in i):
        entreprise['Microsoft'] += 1
    elif ('akamai' in i or 'akadns' in i):
        entreprise['Akamai'] += 1
    


nmb_total = sum(entreprise.values())
labels = list(entreprise.keys())
sizes = [entreprise[k] / nmb_total for k in labels]
explode = [0.1 if sizes[i] > 0.05 else 0 for i in range(len(sizes))]
threshold = 0.03 * nmb_total  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels[i] if entreprise[labels[i]] > threshold else '' for i in range(len(labels))]
fig1, ax1 = plt.subplots(nrows=1, ncols=2, figsize=(10, 5))
ax1[0].pie(sizes, explode=explode, labels=labels, autopct=lambda pct: f"{pct:.1f}%", shadow=False, startangle=90)
ax1[0].set_title('Noms des entreprises possédant les domaines résolus')
ax1[0].axis('equal')

entreprise_author = {'Microsoft': 8, 'Akamai': 5}
nmb_total = sum(entreprise_author.values())
labels = list(entreprise_author.keys())
sizes = [entreprise_author[k] / nmb_total for k in labels]
explode = [0.1 if sizes[i] > 0.05 else 0 for i in range(len(sizes))]
threshold = 0.03 * nmb_total  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels[i] if entreprise_author[labels[i]] > threshold else '' for i in range(len(labels))]
ax1[1].pie(sizes, explode=explode, labels=labels, autopct=lambda pct: f"{pct:.1f}%", shadow=False, startangle=90)
ax1[1].set_title('Noms des entreprises possédant les serveurs authoratifs')
ax1[1].axis('equal')
plt.tight_layout()
#plt.savefig('DNS/graph_entreprise.pdf')



    
    
    
        

            
        

    