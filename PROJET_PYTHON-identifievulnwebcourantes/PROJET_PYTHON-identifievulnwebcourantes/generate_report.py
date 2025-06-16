from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from datetime import datetime
import os

def create_summary_chart(xss_count, sql_count, bf_count):
    drawing = Drawing(400, 200)
    data = [(xss_count, sql_count, bf_count)]
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 125
    bc.width = 300
    bc.data = data
    bc.categoryAxis.categoryNames = ['XSS', 'SQL Injection', 'Brute Force']
    bc.bars[0].fillColor = colors.HexColor('#E74C3C')  # Rouge pour XSS
    bc.bars[1].fillColor = colors.HexColor('#C0392B')  # Rouge foncé pour SQL
    bc.bars[2].fillColor = colors.HexColor('#2980B9')  # Bleu pour Brute Force
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(xss_count, sql_count, bf_count) + 1
    bc.valueAxis.valueStep = 1
    drawing.add(bc)
    return drawing

def generate_vulnerability_report(xss_results, sql_results, bruteforce_results, output_file="rapport_vulnerabilites.pdf"):
    # Création du document PDF
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#2C3E50'),
        alignment=1  # Centré
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=18,
        spaceAfter=20,
        textColor=colors.HexColor('#34495E')
    )

    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading3'],
        fontSize=14,
        spaceAfter=10,
        textColor=colors.HexColor('#7F8C8D')
    )

    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=10,
        textColor=colors.HexColor('#2C3E50')
    )

    # En-tête du rapport
    story.append(Paragraph("Rapport de Vulnérabilités Web", title_style))
    story.append(Paragraph("Analyse de Sécurité", subtitle_style))
    story.append(Paragraph(f"Date du scan : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", normal_style))
    
    # Informations des créateurs
    story.append(Spacer(1, 20))
    story.append(Paragraph("Développé par :", section_style))
    creators = [
        "• Florian",
        "• Yoann",
        "• Quentin"
    ]
    for creator in creators:
        story.append(Paragraph(creator, normal_style))
    
    story.append(Spacer(1, 30))

    # Résumé des vulnérabilités
    story.append(Paragraph("Résumé des Vulnérabilités", subtitle_style))
    xss_count = len(xss_results) if xss_results else 0
    sql_count = len(sql_results) if sql_results else 0
    bf_count = len(bruteforce_results) if bruteforce_results else 0
    
    summary_data = [
        ['Type de Vulnérabilité', 'Nombre Détecté', 'Niveau de Risque'],
        ['XSS', str(xss_count), 'Élevé' if xss_count > 0 else 'Faible'],
        ['SQL Injection', str(sql_count), 'Critique' if sql_count > 0 else 'Faible'],
        ['Brute Force', str(bf_count), 'Moyen' if bf_count > 0 else 'Faible']
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 100, 100])
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
    story.append(Spacer(1, 20))

    # Graphique de résumé
    story.append(create_summary_chart(xss_count, sql_count, bf_count))
    story.append(Spacer(1, 30))

    # Section XSS
    story.append(Paragraph("Vulnérabilités XSS Détectées", subtitle_style))
    if xss_results:
        xss_data = [['URL', 'Payload', 'Niveau de Risque']]
        for key, value in xss_results.items():
            xss_data.append([value['URL'], value['Payload'], 'Élevé'])
        
        xss_table = Table(xss_data, colWidths=[250, 200, 100])
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

    # Section SQL Injection
    story.append(Paragraph("Vulnérabilités SQL Injection Détectées", subtitle_style))
    if sql_results:
        sql_data = [['URL', 'Payload', 'Niveau de Risque']]
        for key, value in sql_results.items():
            sql_data.append([value['URL'], value['Payload'], 'Critique'])
        
        sql_table = Table(sql_data, colWidths=[250, 200, 100])
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

    # Section Brute Force
    story.append(Paragraph("Tests de Brute Force", subtitle_style))
    if bruteforce_results:
        bf_data = [['URL', 'Payload', 'Niveau de Risque']]
        for key, value in bruteforce_results.items():
            bf_data.append([value['URL'], str(value['Payload']), 'Moyen'])
        
        bf_table = Table(bf_data, colWidths=[250, 200, 100])
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

    # Recommandations
    story.append(Spacer(1, 30))
    story.append(Paragraph("Recommandations Générales", subtitle_style))
    recommendations = [
        "• Mettre en place une validation stricte des entrées utilisateur",
        "• Utiliser des requêtes préparées pour les opérations SQL",
        "• Implémenter une protection contre les attaques XSS",
        "• Renforcer la politique de mots de passe",
        "• Mettre à jour régulièrement les composants du système",
        "• Utiliser HTTPS pour toutes les communications"
    ]
    for rec in recommendations:
        story.append(Paragraph(rec, normal_style))

    # Pied de page
    story.append(Spacer(1, 30))
    story.append(Paragraph("Ce rapport a été généré automatiquement par l'outil de scan de vulnérabilités web", 
                          ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))

    # Génération du PDF
    doc.build(story)
    return output_file 