import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configuration de la page Streamlit
st.set_page_config(
    page_title="Analyse de Trafic Réseau",
    page_icon="🌐",
    layout="wide"
)

# Titre de l'application
st.title("🌐 Tableau de Bord d'Analyse de Logs Réseau")
st.markdown("Cette application permet d'explorer et de visualiser les données de trafic réseau.")

# Fonction pour charger les données
@st.cache_data
def load_data():
    data = pd.read_csv("C:/Users/Loic/Desktop/r/s2_moi/info_deci/internet+firewall+data/log2.csv")
    # Convertir les colonnes numériques si nécessaire
    numeric_cols = [
        'Source Port', 'Destination Port', 'NAT Source Port', 'NAT Destination Port',
        'Bytes', 'Bytes Sent', 'Bytes Received', 'Packets', 'Elapsed Time (sec)',
        'pkts_sent', 'pkts_received'
    ]
    for col in numeric_cols:
        if col in data.columns:
            data[col] = pd.to_numeric(data[col], errors='coerce')
    
    # Créer des colonnes dérivées pour l'analyse
    data['bytes_per_packet'] = data['Bytes'] / data['Packets']
    data['sent_received_ratio'] = data['Bytes Sent'] / data['Bytes Received'].replace(0, 1)  # Éviter division par zéro
    data['is_incoming'] = data['Bytes Received'] > data['Bytes Sent']
    
    # Catégoriser le temps écoulé
    data['time_category'] = pd.cut(
        data['Elapsed Time (sec)'],
        bins=[0, 10, 60, 300, 1800, float('inf')],
        labels=['0-10s', '10-60s', '1-5min', '5-30min', '>30min']
    )
    
    return data

# Charger les données
try:
    data = load_data()
    st.success(f"Données chargées avec succès: {len(data)} lignes.")
    
    # Afficher un aperçu des données
    with st.expander("Aperçu des données"):
        st.dataframe(data.head(10))
        
        st.subheader("Statistiques de base")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total des connexions", f"{len(data):,}")
        with col2:
            st.metric("Total des octets", f"{data['Bytes'].sum() / (1024*1024):.2f} MB")
        with col3:
            allow_rate = (data['Action'] == 'allow').mean() * 100
            st.metric("Taux d'acceptation", f"{allow_rate:.2f}%")

    # Créer des onglets pour différentes analyses
    tab1, tab2, tab3, tab4 = st.tabs(["Distribution des actions", "Analyse par port", "Analyse temporelle", "Corrélations"])
    
    with tab1:
        st.header("Distribution des actions")
        
        # Graphique de distribution des actions
        action_counts = data['Action'].value_counts().reset_index()
        action_counts.columns = ['Action', 'Count']
        
        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(
                action_counts, 
                values='Count', 
                names='Action',
                title='Distribution des actions',
                color='Action',
                color_discrete_map={
                    'allow': '#00CC96',
                    'deny': '#EF553B',
                    'drop': '#AB63FA',
                    'reset-both': '#FFA15A'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.bar(
                action_counts,
                x='Action',
                y='Count',
                title='Nombre d\'entrées par action',
                color='Action'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.header("Analyse par port")
        
        # Top ports de destination
        top_n = st.slider("Nombre de ports à afficher", 5, 20, 10)
        top_ports = data['Destination Port'].value_counts().nlargest(top_n)
        
        fig = px.bar(
            x=top_ports.index,
            y=top_ports.values,
            labels={'x': 'Port de destination', 'y': 'Nombre de connexions'},
            title=f'Top {top_n} des ports de destination'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Actions par port
        st.subheader("Distribution des actions par port")
        selected_ports = st.multiselect(
            "Sélectionner des ports à analyser",
            options=top_ports.index.tolist(),
            default=top_ports.index[:5].tolist()
        )
        
        if selected_ports:
            port_action_data = data[data['Destination Port'].isin(selected_ports)]
            port_action_counts = port_action_data.groupby(['Destination Port', 'Action']).size().reset_index(name='Count')
            
            fig = px.bar(
                port_action_counts,
                x='Destination Port',
                y='Count',
                color='Action',
                barmode='group',
                title='Actions par port de destination'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Statistiques par port
            port_stats = data[data['Destination Port'].isin(selected_ports)].groupby('Destination Port').agg({
                'Bytes': ['mean', 'sum'],
                'Packets': ['mean', 'sum'],
                'Elapsed Time (sec)': 'mean'
            }).reset_index()
            port_stats.columns = ['Port', 'Bytes Moyen', 'Bytes Total', 'Paquets Moyen', 'Paquets Total', 'Temps Écoulé Moyen']
            port_stats['Bytes Total (MB)'] = port_stats['Bytes Total'] / (1024*1024)
            
            st.dataframe(port_stats)
    
    with tab3:
        st.header("Analyse temporelle")
        
        # Distribution par temps écoulé
        time_counts = data['time_category'].value_counts().sort_index().reset_index()
        time_counts.columns = ['Catégorie de temps', 'Nombre']
        
        fig = px.bar(
            time_counts,
            x='Catégorie de temps',
            y='Nombre',
            title='Distribution des connexions par durée'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Actions par catégorie de temps
        time_action_counts = data.groupby(['time_category', 'Action']).size().reset_index(name='Count')
        
        fig = px.bar(
            time_action_counts,
            x='time_category',
            y='Count',
            color='Action',
            barmode='stack',
            labels={'time_category': 'Catégorie de temps', 'Count': 'Nombre'},
            title='Actions par catégorie de temps'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Bytes moyen par catégorie de temps
        time_bytes = data.groupby('time_category')['Bytes'].mean().reset_index()
        time_bytes['Bytes (KB)'] = time_bytes['Bytes'] / 1024
        
        fig = px.bar(
            time_bytes,
            x='time_category',
            y='Bytes (KB)',
            labels={'time_category': 'Catégorie de temps', 'Bytes (KB)': 'Bytes moyen (KB)'},
            title='Bytes moyen par catégorie de temps'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab4:
        st.header("Corrélations et relations")
        
        # Matrice de corrélation
        numeric_cols = ['Bytes', 'Bytes Sent', 'Bytes Received', 'Packets', 
                        'Elapsed Time (sec)', 'pkts_sent', 'pkts_received']
        corr_matrix = data[numeric_cols].corr()
        
        fig = px.imshow(
            corr_matrix,
            text_auto=True,
            aspect="auto",
            color_continuous_scale='RdBu_r',
            title='Matrice de corrélation'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Scatter plots
        st.subheader("Relation entre variables")
        
        col1, col2 = st.columns(2)
        with col1:
            x_axis = st.selectbox("Axe X", options=numeric_cols, index=3)  # Default to Packets
        with col2:
            y_axis = st.selectbox("Axe Y", options=numeric_cols, index=0)  # Default to Bytes
        
        # Échantillonner les données pour une meilleure visualisation
        sample_size = min(5000, len(data))
        sampled_data = data.sample(sample_size)
        
        fig = px.scatter(
            sampled_data,
            x=x_axis,
            y=y_axis,
            color='Action',
            opacity=0.7,
            title=f'Relation entre {x_axis} et {y_axis}',
            hover_data=['Destination Port', 'Elapsed Time (sec)']
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Distribution bytes par paquet
        st.subheader("Distribution bytes par paquet")
        
        # Créer des catégories de ratio
        ratio_bins = [0, 100, 500, 1000, float('inf')]
        ratio_labels = ['<100 bytes/pkt', '100-500 bytes/pkt', '500-1000 bytes/pkt', '>1000 bytes/pkt']
        
        data['bytes_per_packet_cat'] = pd.cut(
            data['bytes_per_packet'],
            bins=ratio_bins,
            labels=ratio_labels
        )
        
        ratio_counts = data['bytes_per_packet_cat'].value_counts().sort_index().reset_index()
        ratio_counts.columns = ['Catégorie', 'Nombre']
        
        fig = px.pie(
            ratio_counts,
            values='Nombre',
            names='Catégorie',
            title='Distribution par ratio bytes/paquet'
        )
        st.plotly_chart(fig, use_container_width=True)

    # Section pour les anomalies et insights
    st.header("🔍 Détection d'anomalies")
    
    with st.expander("Connexions potentiellement anormales"):
        # Connexions longues avec peu de données
        long_low_data = data[(data['Elapsed Time (sec)'] > 300) & (data['Bytes'] < 1000)]
        st.write(f"Connexions longues (>5min) avec peu de données (<1KB): {len(long_low_data)}")
        
        if not long_low_data.empty:
            st.dataframe(long_low_data.head(10))
        
        # Connexions avec ratio bytes/paquet inhabituel
        abnormal_ratio = data[(data['bytes_per_packet'] > 10000) | (data['bytes_per_packet'] < 10)]
        st.write(f"Connexions avec ratio bytes/paquet inhabituel: {len(abnormal_ratio)}")
        
        if not abnormal_ratio.empty:
            st.dataframe(abnormal_ratio.head(10))
    
    # Insights et recommandations
    st.header("💡 Insights et Recommandations")
    
    # Détecter les ports fréquemment bloqués
    blocked_ports = data[data['Action'].isin(['deny', 'drop', 'reset-both'])]['Destination Port'].value_counts().nlargest(5)
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Ports fréquemment bloqués")
        if not blocked_ports.empty:
            fig = px.bar(
                x=blocked_ports.index,
                y=blocked_ports.values,
                labels={'x': 'Port', 'y': 'Nombre de blocages'},
                title='Top 5 des ports bloqués'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Recommandations")
        allow_rate = (data['Action'] == 'allow').mean() * 100
        
        if allow_rate < 60:
            st.warning(f"Le taux d'acceptation est relativement bas ({allow_rate:.2f}%). Vérifiez les règles de pare-feu.")
        else:
            st.success(f"Le taux d'acceptation est bon ({allow_rate:.2f}%).")
            
        # Identifier les ports sensibles
        port_445_count = len(data[data['Destination Port'] == 445])
        if port_445_count > 0:
            port_445_block_rate = (data[data['Destination Port'] == 445]['Action'] != 'allow').mean() * 100
            if port_445_block_rate > 80:
                st.info(f"Le port 445 (SMB) est bien protégé avec un taux de blocage de {port_445_block_rate:.2f}%.")
            else:
                st.warning(f"Attention: Le port 445 (SMB) a un taux de blocage de seulement {port_445_block_rate:.2f}%.")
        
        # Autres recommandations basées sur l'analyse
        st.info("""
        Recommandations générales basées sur l'analyse:
        1. Examinez les connexions de longue durée avec peu de données transférées
        2. Vérifiez les connexions avec des ratios bytes/paquet inhabituels
        3. Surveillez les ports connus pour les services sensibles (80, 443, 445, 3389)
        4. Analysez les motifs de trafic pour détecter des comportements anormaux
        """)

except Exception as e:
    st.error(f"Erreur lors du chargement ou de l'analyse des données: {e}")
    st.info("Veuillez vérifier que le fichier 'log2.csv' est correctement formaté et disponible.")