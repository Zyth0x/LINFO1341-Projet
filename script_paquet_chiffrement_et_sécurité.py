import pyshark 

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

#------------------------------------------------------------- Chiffrement et sécurité -------------------------------------------------------------

certificate = []

for f in file:
    # Open the capture file
    cap = pyshark.FileCapture(f)
    

    # Trier pour avoir que les TLS
    organizationname = []
    number = 0
    for packet in cap:
        if packet.layers[-1].layer_name == 'tls':
                    print(packet.tls.record_content_type)
                    organizationName = []
                    for i in range(len(packet.tls.x509sat_printablestring.fields)):
                            if packet.tls.x509sat_printablestring.fields[i].show not in organizationName:
                                organizationName.append(packet.tls.x509sat_printablestring.fields[i].show)
                
                    utcTime = []
                    for i in range(len(packet.tls.x509af_utctime.fields)):
                        if packet.tls.x509af_utctime.fields[i].show not in utcTime:
                            utcTime.append(packet.tls.x509af_utctime.fields[i].show)
                    
                    algorithm = []
                    for i in range(len(packet.tls.x509af_algorithm_id.fields)):
                        if packet.tls.x509af_algorithm_id.fields[0].showname_value.split(' ')[1][1:-1] not in algorithm:
                            algorithm.append(packet.tls.x509af_algorithm_id.fields[i].showname_value.split(' ')[1][1:-1])
                    
                    organizationname.append((number, organizationName, utcTime, algorithm))
            

        number += 1
    
    certificate.append(title[file.index(f)] + " : " + str(organizationname))
    

    cap.close()

            
print(certificate)
                
    

    
            
