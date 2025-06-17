from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.textlabels import Label
from datetime import datetime
import os
import platform
import socket

def get_system_info():
    """Récupère les informations système pour le rapport"""
    return {
        'system': platform.system(),
        'release': platform.release(),
        'machine': platform.machine(),
        'hostname': socket.gethostname(),
        'ip': socket.gethostbyname(socket.gethostname())
    }

def create_summary_chart(xss_count, sql_count, bf_count):
    """Crée un graphique en barres pour le résumé des vulnérabilités"""
    drawing = Drawing(400, 250)
    
    # Graphique en barres
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 150
    bc.width = 300
    bc.data = [(xss_count, sql_count, bf_count)]
    bc.categoryAxis.categoryNames = ['XSS', 'SQL Injection', 'Brute Force']
    bc.bars[0].fillColor = colors.HexColor('#E74C3C')
    bc.bars[1].fillColor = colors.HexColor('#C0392B')
    bc.bars[2].fillColor = colors.HexColor('#2980B9')
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(xss_count, sql_count, bf_count) + 1
    bc.valueAxis.valueStep = 1
    
    # Ajout d'un titre au graphique
    title = String(200, 220, "Résumé des Vulnérabilités Détectées", 
                  fontSize=14, fillColor=colors.HexColor('#2C3E50'))
    title.textAnchor = 'middle'
    
    drawing.add(bc)
    drawing.add(title)
    return drawing

def create_risk_pie_chart(xss_count, sql_count, bf_count):
    """Crée un graphique en camembert pour la répartition des risques"""
    drawing = Drawing(400, 250)
    
    pie = Pie()
    pie.x = 150
    pie.y = 50
    pie.width = 150
    pie.height = 150
    pie.data = [xss_count, sql_count, bf_count]
    pie.labels = ['XSS', 'SQL Injection', 'Brute Force']
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.HexColor('#E74C3C')
    pie.slices[1].fillColor = colors.HexColor('#C0392B')
    pie.slices[2].fillColor = colors.HexColor('#2980B9')
    
    # Ajout d'un titre au graphique
    title = String(200, 220, "Répartition des Risques", 
                  fontSize=14, fillColor=colors.HexColor('#2C3E50'))
    title.textAnchor = 'middle'
    
    drawing.add(pie)
    drawing.add(title)
    return drawing

def generate_vulnerability_report(xss_results, sql_results, bruteforce_results, output_file="rapport_vulnerabilites.pdf"):
    """Génère un rapport détaillé des vulnérabilités web"""
    # Création du document PDF
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Styles personnalisés améliorés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        textColor=colors.HexColor('#2C3E50'),
        alignment=1,
        leading=32
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=20,
        spaceAfter=20,
        textColor=colors.HexColor('#34495E'),
        leading=24
    )

    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading3'],
        fontSize=16,
        spaceAfter=10,
        textColor=colors.HexColor('#7F8C8D'),
        leading=20
    )

    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=10,
        textColor=colors.HexColor('#2C3E50'),
        leading=14
    )

    # En-tête du rapport
    story.append(Paragraph("Rapport de Vulnérabilités Web", title_style))
    story.append(Paragraph("Analyse de Sécurité Détaillée", subtitle_style))
    
    # Informations système
    system_info = get_system_info()
    story.append(Paragraph("Informations Système", section_style))
    system_data = [
        ['Système', system_info['system']],
        ['Version', system_info['release']],
        ['Architecture', system_info['machine']],
        ['Nom d\'hôte', system_info['hostname']],
        ['Adresse IP', system_info['ip']],
        ['Date du scan', datetime.now().strftime('%d/%m/%Y %H:%M:%S')]
    ]
    
    system_table = Table(system_data, colWidths=[150, 300])
    system_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2C3E50')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7'))
    ]))
    story.append(system_table)
    story.append(Spacer(1, 20))
    
    # Informations des créateurs
    story.append(Paragraph("Équipe de Développement", section_style))
    creators = [
        "• Florian - Expert en Sécurité Web",
        "• Yoann - Spécialiste en Analyse de Vulnérabilités",
        "• Quentin - Développeur Full-Stack"
    ]
    for creator in creators:
        story.append(Paragraph(creator, normal_style))
    
    story.append(Spacer(1, 30))

    # Résumé des vulnérabilités
    story.append(Paragraph("Résumé des Vulnérabilités", subtitle_style))
    xss_count = len(xss_results) if xss_results else 0
    sql_count = len(sql_results) if sql_results else 0
    bf_count = len(bruteforce_results) if bruteforce_results else 0
    
    # Graphiques
    story.append(create_summary_chart(xss_count, sql_count, bf_count))
    story.append(Spacer(1, 20))
    story.append(create_risk_pie_chart(xss_count, sql_count, bf_count))
    story.append(Spacer(1, 30))
    
    summary_data = [
        ['Type de Vulnérabilité', 'Nombre Détecté', 'Niveau de Risque', 'Impact Potentiel'],
        ['XSS', str(xss_count), 'Élevé' if xss_count > 0 else 'Faible', 'Vol de données, Session Hijacking'],
        ['SQL Injection', str(sql_count), 'Critique' if sql_count > 0 else 'Faible', 'Accès non autorisé à la base de données'],
        ['Brute Force', str(bf_count), 'Moyen' if bf_count > 0 else 'Faible', 'Compromission des comptes']
    ]
    
    summary_table = Table(summary_data, colWidths=[150, 100, 100, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 30))

    # Section XSS détaillée
    story.append(PageBreak())
    story.append(Paragraph("Vulnérabilités XSS Détectées", subtitle_style))
    if xss_results:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Les attaques XSS (Cross-Site Scripting) permettent à un attaquant d'injecter du code malveillant dans des pages web vues par d'autres utilisateurs.", normal_style))
        story.append(Spacer(1, 10))
        
        xss_data = [['URL', 'Payload', 'Niveau de Risque', 'Recommandation']]
        for key, value in xss_results.items():
            xss_data.append([
                value['URL'], 
                value['Payload'], 
                'Élevé',
                'Valider et échapper les entrées utilisateur'
            ])
        
        xss_table = Table(xss_data, colWidths=[200, 150, 100, 150])
        xss_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
        ]))
        story.append(xss_table)
    else:
        story.append(Paragraph("✅ Aucune vulnérabilité XSS détectée", normal_style))
    story.append(Spacer(1, 20))

    # Section SQL Injection détaillée
    story.append(Paragraph("Vulnérabilités SQL Injection Détectées", subtitle_style))
    if sql_results:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Les attaques par injection SQL permettent à un attaquant d'exécuter des commandes SQL malveillantes sur la base de données.", normal_style))
        story.append(Spacer(1, 10))
        
        sql_data = [['URL', 'Payload', 'Niveau de Risque', 'Recommandation']]
        for key, value in sql_results.items():
            sql_data.append([
                value['URL'], 
                value['Payload'], 
                'Critique',
                'Utiliser des requêtes préparées'
            ])
        
        sql_table = Table(sql_data, colWidths=[200, 150, 100, 150])
        sql_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#C0392B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
        ]))
        story.append(sql_table)
    else:
        story.append(Paragraph("✅ Aucune vulnérabilité SQL Injection détectée", normal_style))
    story.append(Spacer(1, 20))

    # Section Brute Force détaillée
    story.append(Paragraph("Tests de Brute Force", subtitle_style))
    if bruteforce_results:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Les attaques par force brute tentent de deviner les identifiants en essayant toutes les combinaisons possibles.", normal_style))
        story.append(Spacer(1, 10))
        
        bf_data = [['URL', 'Payload', 'Niveau de Risque', 'Recommandation']]
        for key, value in bruteforce_results.items():
            bf_data.append([
                value['URL'], 
                str(value['Payload']), 
                'Moyen',
                'Limiter les tentatives de connexion'
            ])
        
        bf_table = Table(bf_data, colWidths=[200, 150, 100, 150])
        bf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2980B9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
        ]))
        story.append(bf_table)
    else:
        story.append(Paragraph("✅ Aucun test de brute force effectué", normal_style))

    # Recommandations détaillées
    story.append(PageBreak())
    story.append(Paragraph("Recommandations Détaillées", subtitle_style))
    
    recommendations = [
        ("Validation des Entrées", [
            "• Mettre en place une validation stricte des entrées utilisateur",
            "• Utiliser des expressions régulières pour valider les formats",
            "• Implémenter une liste blanche de caractères autorisés"
        ]),
        ("Protection contre les Injections SQL", [
            "• Utiliser des requêtes préparées pour toutes les opérations SQL",
            "• Éviter la concaténation directe des entrées utilisateur dans les requêtes",
            "• Implémenter un système de logging des requêtes SQL"
        ]),
        ("Sécurité XSS", [
            "• Échapper correctement les caractères spéciaux",
            "• Utiliser des en-têtes de sécurité comme Content-Security-Policy",
            "• Implémenter une validation côté serveur"
        ]),
        ("Protection contre le Brute Force", [
            "• Limiter le nombre de tentatives de connexion",
            "• Implémenter un délai croissant entre les tentatives",
            "• Utiliser l'authentification à deux facteurs"
        ]),
        ("Sécurité Générale", [
            "• Mettre à jour régulièrement tous les composants du système",
            "• Utiliser HTTPS pour toutes les communications",
            "• Implémenter une politique de mots de passe forte"
        ])
    ]
    
    for category, items in recommendations:
        story.append(Paragraph(category, section_style))
        for item in items:
            story.append(Paragraph(item, normal_style))
        story.append(Spacer(1, 10))

    # Pied de page
    story.append(Spacer(1, 30))
    story.append(Paragraph("Ce rapport a été généré automatiquement par l'outil de scan de vulnérabilités web", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))
    story.append(Paragraph(f"Date de génération : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))

    # Génération du PDF
    doc.build(story)
    return output_file

def create_network_chart(syn_flood_count, arp_spoofing_count, malicious_count):
    """Crée un graphique en barres pour le résumé des détections réseau"""
    drawing = Drawing(400, 250)
    
    # Graphique en barres
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 150
    bc.width = 300
    bc.data = [(syn_flood_count, arp_spoofing_count, malicious_count)]
    bc.categoryAxis.categoryNames = ['SYN Flood', 'ARP Spoofing', 'Malicious Payload']
    bc.bars[0].fillColor = colors.HexColor('#E74C3C')
    bc.bars[1].fillColor = colors.HexColor('#C0392B')
    bc.bars[2].fillColor = colors.HexColor('#2980B9')
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(syn_flood_count, arp_spoofing_count, malicious_count) + 1
    bc.valueAxis.valueStep = 1
    
    # Ajout d'un titre au graphique
    title = String(200, 220, "Résumé des Détections Réseau", 
                  fontSize=14, fillColor=colors.HexColor('#2C3E50'))
    title.textAnchor = 'middle'
    
    drawing.add(bc)
    drawing.add(title)
    return drawing

def create_traffic_chart(ip_data):
    """Crée un graphique en barres pour le trafic par IP"""
    drawing = Drawing(400, 250)
    
    # Graphique en barres
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 150
    bc.width = 300
    
    # Extraction des données de trafic
    ips = list(ip_data.keys())
    traffic = list(ip_data.values())
    
    # Vérification si nous avons des données
    if not traffic:
        # Si pas de données, créer un graphique vide avec un message
        bc.data = [(0,)]
        bc.categoryAxis.categoryNames = ['Aucune donnée']
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 1
        bc.valueAxis.valueStep = 1
    else:
        # Si nous avons des données, créer le graphique normal
        bc.data = [traffic]
        bc.categoryAxis.categoryNames = ips
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = max(traffic) + 100
        bc.valueAxis.valueStep = max(1, max(traffic) // 5)
    
    bc.bars[0].fillColor = colors.HexColor('#3498DB')
    
    # Ajout d'un titre au graphique
    title = String(200, 220, "Trafic par Adresse IP", 
                  fontSize=14, fillColor=colors.HexColor('#2C3E50'))
    title.textAnchor = 'middle'
    
    drawing.add(bc)
    drawing.add(title)
    return drawing

def generate_network_report(network_data, output_file="rapport_reseau.pdf"):
    """Génère un rapport détaillé de l'analyse réseau"""
    # Création du document PDF
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Styles personnalisés améliorés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        textColor=colors.HexColor('#2C3E50'),
        alignment=1,
        leading=32
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=20,
        spaceAfter=20,
        textColor=colors.HexColor('#34495E'),
        leading=24
    )

    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading3'],
        fontSize=16,
        spaceAfter=10,
        textColor=colors.HexColor('#7F8C8D'),
        leading=20
    )

    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=10,
        textColor=colors.HexColor('#2C3E50'),
        leading=14
    )

    # En-tête du rapport
    story.append(Paragraph("Rapport d'Analyse Réseau", title_style))
    story.append(Paragraph("Analyse de Sécurité Réseau Détaillée", subtitle_style))
    
    # Informations système
    system_info = get_system_info()
    story.append(Paragraph("Informations Système", section_style))
    system_data = [
        ['Système', system_info['system']],
        ['Version', system_info['release']],
        ['Architecture', system_info['machine']],
        ['Nom d\'hôte', system_info['hostname']],
        ['Adresse IP', system_info['ip']],
        ['Date du scan', datetime.now().strftime('%d/%m/%Y %H:%M:%S')]
    ]
    
    system_table = Table(system_data, colWidths=[150, 300])
    system_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2C3E50')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7'))
    ]))
    story.append(system_table)
    story.append(Spacer(1, 20))
    
    # Informations des créateurs
    story.append(Paragraph("Équipe de Développement", section_style))
    creators = [
        "• Florian - Expert en Sécurité Réseau",
        "• Yoann - Spécialiste en Analyse de Trafic",
        "• Quentin - Développeur Full-Stack"
    ]
    for creator in creators:
        story.append(Paragraph(creator, normal_style))
    
    story.append(Spacer(1, 30))

    # Résumé des détections
    story.append(Paragraph("Résumé des Détections", subtitle_style))
    
    # Extraction des données
    syn_flood_count = network_data.get('DETECT_SYN_FLOOD', 0)
    arp_spoofing_count = network_data.get('DETECT_ARP_SPOOFING', 0)
    malicious_count = len(network_data.get('DETECT_MALICIOUS_PAYLOAD', {}))
    ip_data = network_data.get('CHECK_IP', {})
    
    # Graphiques
    story.append(create_network_chart(syn_flood_count, arp_spoofing_count, malicious_count))
    story.append(Spacer(1, 20))
    story.append(create_traffic_chart(ip_data))
    story.append(Spacer(1, 30))
    
    summary_data = [
        ['Type de Détection', 'Nombre Détecté', 'Niveau de Risque', 'Impact Potentiel'],
        ['SYN Flood', str(syn_flood_count), 'Élevé' if syn_flood_count > 0 else 'Faible', 'Déni de Service'],
        ['ARP Spoofing', str(arp_spoofing_count), 'Critique' if arp_spoofing_count > 0 else 'Faible', 'Man in the Middle'],
        ['Malicious Payload', str(malicious_count), 'Moyen' if malicious_count > 0 else 'Faible', 'Exécution de Code']
    ]
    
    summary_table = Table(summary_data, colWidths=[150, 100, 100, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 30))

    # Section SYN Flood détaillée
    story.append(PageBreak())
    story.append(Paragraph("Détections SYN Flood", subtitle_style))
    if syn_flood_count > 0:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Une attaque SYN Flood est une forme d'attaque par déni de service qui exploite le processus de poignée de main TCP à trois voies.", normal_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Nombre d'attaques SYN Flood détectées : {syn_flood_count}", normal_style))
        story.append(Paragraph("Impact :", section_style))
        story.append(Paragraph("• Surcharge des ressources du serveur", normal_style))
        story.append(Paragraph("• Indisponibilité du service", normal_style))
        story.append(Paragraph("• Perte de connectivité réseau", normal_style))
    else:
        story.append(Paragraph("✅ Aucune attaque SYN Flood détectée", normal_style))
    story.append(Spacer(1, 20))

    # Section ARP Spoofing détaillée
    story.append(Paragraph("Détections ARP Spoofing", subtitle_style))
    if arp_spoofing_count > 0:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("L'ARP Spoofing est une technique d'attaque qui permet à un attaquant d'intercepter le trafic réseau en usurpant l'adresse MAC d'un autre appareil.", normal_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Nombre d'attaques ARP Spoofing détectées : {arp_spoofing_count}", normal_style))
        story.append(Paragraph("Impact :", section_style))
        story.append(Paragraph("• Interception du trafic réseau", normal_style))
        story.append(Paragraph("• Vol de données sensibles", normal_style))
        story.append(Paragraph("• Attaques de type Man in the Middle", normal_style))
    else:
        story.append(Paragraph("✅ Aucune attaque ARP Spoofing détectée", normal_style))
    story.append(Spacer(1, 20))

    # Section Malicious Payload détaillée
    story.append(Paragraph("Détections de Payloads Malveillants", subtitle_style))
    if malicious_count > 0:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Les payloads malveillants sont des données ou du code conçus pour exploiter des vulnérabilités ou exécuter des actions non autorisées.", normal_style))
        story.append(Spacer(1, 10))
        
        malicious_data = [['IP', 'Type de Payload', 'Niveau de Risque', 'Recommandation']]
        for ip, payload in network_data.get('DETECT_MALICIOUS_PAYLOAD', {}).items():
            malicious_data.append([
                ip, 
                str(payload), 
                'Moyen',
                'Analyser et bloquer le trafic suspect'
            ])
        
        malicious_table = Table(malicious_data, colWidths=[150, 200, 100, 150])
        malicious_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2980B9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
        ]))
        story.append(malicious_table)
    else:
        story.append(Paragraph("✅ Aucun payload malveillant détecté", normal_style))

    # Analyse du trafic
    story.append(PageBreak())
    story.append(Paragraph("Analyse du Trafic Réseau", subtitle_style))
    story.append(Paragraph("Statistiques de Trafic par IP", section_style))
    
    traffic_data = [['Adresse IP', 'Nombre de Paquets', 'Niveau de Trafic']]
    for ip, count in ip_data.items():
        traffic_level = 'Élevé' if count > 500 else 'Moyen' if count > 100 else 'Faible'
        traffic_data.append([ip, str(count), traffic_level])
    
    traffic_table = Table(traffic_data, colWidths=[150, 150, 150])
    traffic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27AE60')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
    ]))
    story.append(traffic_table)

    # Recommandations détaillées
    story.append(Spacer(1, 30))
    story.append(Paragraph("Recommandations Détaillées", subtitle_style))
    
    recommendations = [
        ("Protection contre les SYN Flood", [
            "• Configurer un pare-feu pour limiter le nombre de connexions SYN",
            "• Implémenter la protection SYN cookies",
            "• Utiliser des systèmes de détection d'intrusion (IDS)"
        ]),
        ("Protection contre l'ARP Spoofing", [
            "• Activer la détection d'ARP Spoofing sur les switches",
            "• Utiliser des tables ARP statiques pour les équipements critiques",
            "• Implémenter des outils de surveillance ARP"
        ]),
        ("Gestion des Payloads Malveillants", [
            "• Mettre en place un système de filtrage de paquets",
            "• Utiliser un IDS/IPS pour détecter les payloads malveillants",
            "• Analyser régulièrement les logs de trafic"
        ]),
        ("Surveillance du Trafic", [
            "• Mettre en place une surveillance continue du trafic réseau",
            "• Définir des seuils d'alerte pour le trafic anormal",
            "• Utiliser des outils d'analyse de trafic en temps réel"
        ]),
        ("Sécurité Générale", [
            "• Mettre à jour régulièrement les équipements réseau",
            "• Segmenter le réseau en zones de sécurité",
            "• Implémenter une politique de sécurité réseau stricte"
        ])
    ]
    
    for category, items in recommendations:
        story.append(Paragraph(category, section_style))
        for item in items:
            story.append(Paragraph(item, normal_style))
        story.append(Spacer(1, 10))

    # Pied de page
    story.append(Spacer(1, 30))
    story.append(Paragraph("Ce rapport a été généré automatiquement par l'outil d'analyse réseau", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))
    story.append(Paragraph(f"Date de génération : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))

    # Génération du PDF
    doc.build(story)
    return output_file

def create_port_chart(open_ports, closed_ports):
    """Crée un graphique en barres pour le résumé des ports"""
    drawing = Drawing(400, 250)
    
    # Graphique en barres
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 150
    bc.width = 300
    bc.data = [(len(open_ports), len(closed_ports))]
    bc.categoryAxis.categoryNames = ['Ports Ouverts', 'Ports Fermés']
    bc.bars[0].fillColor = colors.HexColor('#E74C3C')
    bc.bars[1].fillColor = colors.HexColor('#27AE60')
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(len(open_ports), len(closed_ports)) + 1
    bc.valueAxis.valueStep = 1
    
    # Ajout d'un titre au graphique
    title = String(200, 220, "Résumé du Scan de Ports", 
                  fontSize=14, fillColor=colors.HexColor('#2C3E50'))
    title.textAnchor = 'middle'
    
    drawing.add(bc)
    drawing.add(title)
    return drawing

def generate_port_scan_report(scan_results, ip, start_port, end_port, output_file="rapport_scan_ports.pdf"):
    """Génère un rapport détaillé du scan de ports"""
    # Création du document PDF
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Styles personnalisés améliorés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        textColor=colors.HexColor('#2C3E50'),
        alignment=1,
        leading=32
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=20,
        spaceAfter=20,
        textColor=colors.HexColor('#34495E'),
        leading=24
    )

    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading3'],
        fontSize=16,
        spaceAfter=10,
        textColor=colors.HexColor('#7F8C8D'),
        leading=20
    )

    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=10,
        textColor=colors.HexColor('#2C3E50'),
        leading=14
    )

    # En-tête du rapport
    story.append(Paragraph("Rapport de Scan de Ports", title_style))
    story.append(Paragraph("Analyse de Sécurité Réseau", subtitle_style))
    
    # Informations système
    system_info = get_system_info()
    story.append(Paragraph("Informations Système", section_style))
    system_data = [
        ['Système', system_info['system']],
        ['Version', system_info['release']],
        ['Architecture', system_info['machine']],
        ['Nom d\'hôte', system_info['hostname']],
        ['Adresse IP', system_info['ip']],
        ['Date du scan', datetime.now().strftime('%d/%m/%Y %H:%M:%S')]
    ]
    
    system_table = Table(system_data, colWidths=[150, 300])
    system_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2C3E50')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7'))
    ]))
    story.append(system_table)
    story.append(Spacer(1, 20))
    
    # Informations du scan
    story.append(Paragraph("Paramètres du Scan", section_style))
    scan_data = [
        ['Cible', ip],
        ['Port de début', str(start_port)],
        ['Port de fin', str(end_port)],
        ['Plage de ports', f"{end_port - start_port + 1} ports"]
    ]
    
    scan_table = Table(scan_data, colWidths=[150, 300])
    scan_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2C3E50')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7'))
    ]))
    story.append(scan_table)
    story.append(Spacer(1, 30))

    # Résumé des résultats
    story.append(Paragraph("Résumé des Résultats", subtitle_style))
    
    # Traitement des résultats du scan
    open_ports = []
    closed_ports = []
    
    # Extraction des ports ouverts depuis le dictionnaire de résultats
    if isinstance(scan_results, dict):
        for port_info in scan_results.values():
            if isinstance(port_info, dict) and "Port ouvert" in port_info:
                open_ports.append(port_info["Port ouvert"])
    
    # Tous les autres ports sont considérés comme fermés
    closed_ports = [port for port in range(start_port, end_port + 1) if port not in open_ports]
    
    # Graphique
    story.append(create_port_chart(open_ports, closed_ports))
    story.append(Spacer(1, 30))
    
    total_ports = len(open_ports) + len(closed_ports)
    open_percentage = (len(open_ports) / total_ports * 100) if total_ports > 0 else 0
    closed_percentage = (len(closed_ports) / total_ports * 100) if total_ports > 0 else 0
    
    summary_data = [
        ['Statut', 'Nombre', 'Pourcentage', 'Niveau de Risque'],
        ['Ports Ouverts', str(len(open_ports)), 
         f"{open_percentage:.1f}%",
         'Élevé' if len(open_ports) > 0 else 'Faible'],
        ['Ports Fermés', str(len(closed_ports)),
         f"{closed_percentage:.1f}%",
         'Faible']
    ]
    
    summary_table = Table(summary_data, colWidths=[150, 100, 100, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 30))

    # Détails des ports ouverts
    story.append(PageBreak())
    story.append(Paragraph("Détails des Ports Ouverts", subtitle_style))
    if open_ports:
        story.append(Paragraph("Description", section_style))
        story.append(Paragraph("Les ports ouverts représentent des points d'entrée potentiels pour les attaquants. Chaque port ouvert doit être analysé et sécurisé.", normal_style))
        story.append(Spacer(1, 10))
        
        ports_data = [['Port', 'Service Commun', 'Niveau de Risque', 'Recommandation']]
        for port in sorted(open_ports):
            service = "Inconnu"
            risk = "Moyen"
            recommendation = "Analyser et sécuriser"
            
            # Identification des services communs
            if port == 21:
                service = "FTP"
                risk = "Élevé"
                recommendation = "Utiliser SFTP ou FTPS"
            elif port == 22:
                service = "SSH"
                risk = "Moyen"
                recommendation = "Utiliser des clés SSH"
            elif port == 23:
                service = "Telnet"
                risk = "Critique"
                recommendation = "Désactiver et utiliser SSH"
            elif port == 25:
                service = "SMTP"
                risk = "Moyen"
                recommendation = "Configurer SPF et DKIM"
            elif port == 80:
                service = "HTTP"
                risk = "Moyen"
                recommendation = "Utiliser HTTPS"
            elif port == 443:
                service = "HTTPS"
                risk = "Faible"
                recommendation = "Maintenir les certificats"
            elif port == 3306:
                service = "MySQL"
                risk = "Élevé"
                recommendation = "Restreindre l'accès"
            elif port == 135:
                service = "MSRPC"
                risk = "Élevé"
                recommendation = "Restreindre l'accès RPC"
            
            ports_data.append([str(port), service, risk, recommendation])
        
        ports_table = Table(ports_data, colWidths=[100, 150, 100, 150])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2C3E50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F6FA')])
        ]))
        story.append(ports_table)
    else:
        story.append(Paragraph("✅ Aucun port ouvert détecté", normal_style))
    story.append(Spacer(1, 20))

    # Recommandations détaillées
    story.append(Paragraph("Recommandations Détaillées", subtitle_style))
    
    recommendations = [
        ("Sécurité des Ports", [
            "• Fermer tous les ports non essentiels",
            "• Utiliser un pare-feu pour filtrer le trafic",
            "• Mettre en place des règles de filtrage strictes"
        ]),
        ("Surveillance", [
            "• Mettre en place une surveillance continue des ports",
            "• Configurer des alertes pour les nouveaux ports ouverts",
            "• Analyser régulièrement les logs de connexion"
        ]),
        ("Bonnes Pratiques", [
            "• Maintenir les services à jour",
            "• Utiliser des protocoles sécurisés (HTTPS, SFTP, etc.)",
            "• Implémenter une politique de sécurité stricte"
        ]),
        ("Documentation", [
            "• Documenter tous les ports ouverts",
            "• Maintenir un inventaire des services",
            "• Créer des procédures de réponse aux incidents"
        ])
    ]
    
    for category, items in recommendations:
        story.append(Paragraph(category, section_style))
        for item in items:
            story.append(Paragraph(item, normal_style))
        story.append(Spacer(1, 10))

    # Pied de page
    story.append(Spacer(1, 30))
    story.append(Paragraph("Ce rapport a été généré automatiquement par l'outil de scan de ports", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))
    story.append(Paragraph(f"Date de génération : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))

    # Génération du PDF
    doc.build(story)
    return output_file 