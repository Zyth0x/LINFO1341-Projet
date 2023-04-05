import pyshark
import matplotlib.pyplot as plt
import numpy as np

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

bytes = []
da = []
for f in file:
    # Open the capture file
    cap = pyshark.FileCapture(f)
    start_time = float(cap[0].sniff_timestamp)

    data = {}
    number_of_packets = []
    n = 0
    for packet in cap:
        n += 1
    
        time = float(packet.sniff_timestamp)
        if (time - start_time) > 2:
            number_of_packets.append(n)
            start_time = time
        
        if packet.highest_layer not in data:
            data[packet.highest_layer] = int(packet.length.main_field.show)
        else:
            data[packet.highest_layer] += int(packet.length.main_field.show)
        
    number_of_packets.append(n)
    da.append((title[file.index(f)],number_of_packets))

    data['UDP'] = data['DATA']
    if '_WS.MALFORMED' in data:
        data['MALFORMED'] = data['_WS.MALFORMED']
        data.pop('_WS.MALFORMED')
    data.pop('DATA')


    # Faire un graphe avec les données en pourcentage
    
    bytes.append((title[file.index(f)],data))

    cap.close()

final_data = []
for d in da:
    if len(d[1]) < 20:
        final_data.append(d[1])
    else:
        final_data.append(d[1][:20])

# Création du graphique
fig, ax = plt.subplots(figsize=(10, 6))
#index = np.arange(20) * 2  # Index des barres (toutes les 2 secondes)
bar_width = 0.15  # Largeur des barres
opacity = 0.8

# Pour chaque fichier, créer un groupe de barres
for i in range(len(da)):
    ax.bar((np.arange(len(final_data[i]))*2) + i*bar_width, final_data[i], bar_width, alpha=opacity, label=title[i])

ax.set_xlabel('Temps (en secondes)')
ax.set_ylabel('Nombre de paquets')
ax.set_title('Nombre de paquets échangés par seconde')
#ax.set_xticks((np.arange(len(final_data[i]))*2) + bar_width*(len(title)-1)/2)
#ax.set_xticklabels([(i+1)*2 for i in range(20)])  # Afficher les temps toutes les 2 secondes
ax.legend()

fig.tight_layout()
plt.savefig('Application/nombre_paquets.pdf')


# Pour les scénarios d'appel simple
fig, axs = plt.subplots(nrows=2, ncols=2, figsize=(10, 8))
fig.suptitle('Répartition des bytes par scénario d\'appel simple')

nmb_total_bytes_1 = sum(bytes[0][1].values())
labels_1 = [k for k in bytes[0][1].keys()]
sizes_1 = [bytes[0][1][k] / nmb_total_bytes_1 for k in bytes[0][1].keys()]
explode = [0.1 if sizes_1[i] > 0.05 else 0 for i in range(len(sizes_1))]
threshold = 0.03 * nmb_total_bytes_1  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_1[i] if bytes[0][1][labels_1[i]] > threshold else '' for i in range(len(labels_1))]
axs[0,0].pie(sizes_1,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[0,0].set_title(bytes[0][0])

nmb_total_bytes_2 = sum(bytes[1][1].values())
sizes_2 = [bytes[1][1][k] / nmb_total_bytes_2 for k in bytes[1][1].keys()]
labels_2 = [k for k in bytes[1][1].keys()]
explode = [0.1 if sizes_2[i] > 0.05 else 0 for i in range(len(sizes_2))]
threshold = 0.03 * nmb_total_bytes_2  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_2[i] if bytes[1][1][labels_2[i]] > threshold else '' for i in range(len(labels_2))]
axs[0,1].pie(sizes_2,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[0,1].set_title(bytes[1][0])

nmb_total_bytes_3 = sum(bytes[2][1].values())
sizes_3 = [bytes[2][1][k] / nmb_total_bytes_3 for k in bytes[2][1].keys()]
labels_3 = [k for k in bytes[2][1].keys()]
explode = [0.1 if sizes_3[i] > 0.05 else 0 for i in range(len(sizes_3))]
threshold = 0.03 * nmb_total_bytes_3  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_3[i] if bytes[2][1][labels_3[i]] > threshold else '' for i in range(len(labels_3))]
axs[1,0].pie(sizes_3,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[1,0].set_title(bytes[2][0])

nmb_total_bytes_4 = sum(bytes[3][1].values())
sizes_4 = [bytes[3][1][k] / nmb_total_bytes_4 for k in bytes[3][1].keys()]
labels_4 = [k for k in bytes[3][1].keys()]
explode = [0.1 if sizes_4[i] > 0.05 else 0 for i in range(len(sizes_4))]
threshold = 0.03 * nmb_total_bytes_4  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_4[i] if bytes[3][1][labels_4[i]] > threshold else '' for i in range(len(labels_4))]
axs[1,1].pie(sizes_4,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[1,1].set_title(bytes[3][0])

plt.savefig('Application/bytes_appel_simple.pdf')


# Pour les scénarios d'appel vidéo
fig, axs = plt.subplots(nrows=1, ncols=3, figsize=(8, 5))
fig.suptitle('Répartition des bytes par scénario d\'appel vidéo')

nmb_total_bytes_5 = sum(bytes[5][1].values())
sizes_5 = [bytes[5][1][k] / nmb_total_bytes_5 for k in bytes[5][1].keys()]
labels_5 = [k for k in bytes[5][1].keys()]
explode = [0.1 if sizes_5[i] > 0.05 else 0 for i in range(len(sizes_5))]
threshold = 0.03 * nmb_total_bytes_5  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_5[i] if bytes[5][1][labels_5[i]] > threshold else '' for i in range(len(labels_5))]
axs[0].pie(sizes_5,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[0].set_title(bytes[5][0])

nmb_total_bytes_6 = sum(bytes[6][1].values())
sizes_6 = [bytes[6][1][k] / nmb_total_bytes_6 for k in bytes[6][1].keys()]
labels_6 = [k for k in bytes[6][1].keys()]
explode = [0.1 if sizes_6[i] > 0.05 else 0 for i in range(len(sizes_6))]
threshold = 0.03 * nmb_total_bytes_6  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_6[i] if bytes[6][1][labels_6[i]] > threshold else '' for i in range(len(labels_6))]
axs[1].pie(sizes_6,explode,labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[1].set_title(bytes[6][0])

nmb_total_bytes_7 = sum(bytes[7][1].values())
sizes_7 = [bytes[7][1][k] / nmb_total_bytes_7 for k in bytes[7][1].keys()]
labels_7 = [k for k in bytes[7][1].keys()]
explode = [0.1 if sizes_7[i] > 0.05 else 0 for i in range(len(sizes_7))]
threshold = 0.03 * nmb_total_bytes_7  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_7[i] if bytes[7][1][labels_7[i]] > threshold else '' for i in range(len(labels_7))]
axs[2].pie(sizes_7,explode,labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[2].set_title(bytes[7][0])

plt.savefig('Application/bytes_appel_video.pdf')

# Pour les scénarios de message et de partage de fichiers
fig, axs = plt.subplots(nrows=1, ncols=2, figsize=(10, 4))
fig.suptitle('Répartition des bytes par scénario de message et de partage de fichiers')

nmb_total_bytes_8 = sum(bytes[4][1].values())
sizes_8 = [bytes[4][1][k] / nmb_total_bytes_8 for k in bytes[4][1].keys()]
labels_8 = [k for k in bytes[4][1].keys()]
explode = [0.1 if sizes_8[i] > 0.05 else 0 for i in range(len(sizes_8))]
threshold = 0.03 * nmb_total_bytes_8  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_8[i] if bytes[4][1][labels_8[i]] > threshold else '' for i in range(len(labels_8))]
axs[0].pie(sizes_8,explode,labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[0].set_title(bytes[4][0])

nmb_total_bytes_9 = sum(bytes[8][1].values())
sizes_9 = [bytes[8][1][k] / nmb_total_bytes_9 for k in bytes[8][1].keys()]
labels_9 = [k for k in bytes[8][1].keys()]
explode = [0.1 if sizes_9[i] > 0.05 else 0 for i in range(len(sizes_9))]
threshold = 0.03 * nmb_total_bytes_9  # seuil de 3%
# Filtrage des étiquettes avec une valeur inférieure ou égale à 3%
labels_filtered = [labels_9[i] if bytes[8][1][labels_9[i]] > threshold else '' for i in range(len(labels_9))]
axs[1].pie(sizes_9,explode, labels_filtered, autopct=lambda pct: f"{pct:.1f}%" if pct > 2.5 else '', startangle=90)
axs[1].set_title(bytes[8][0])

plt.savefig('Application/bytes_message_fichier.pdf')






