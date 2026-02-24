#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyseur de domaines avancé
Extrait : statut, IP, CMS, technologies, emails, téléphones, titre, mots-clés
"""

import requests
import socket
import re
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

class DomainAnalyzer:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Signatures CMS
        self.cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
            'Joomla': ['/components/com_', '/modules/mod_', 'Joomla!'],
            'Drupal': ['Drupal', '/sites/default/', 'drupal.js'],
            'PrestaShop': ['prestashop', '/modules/blockwishlist/'],
            'Magento': ['Magento', '/skin/frontend/', 'Mage.Cookies'],
            'Shopify': ['cdn.shopify.com', 'shopify', 'Shopify.theme'],
            'Wix': ['wix.com', 'parastorage.com', '_wix'],
            'Squarespace': ['squarespace', 'static1.squarespace.com'],
            'SPIP': ['spip.php', 'spip_', 'SPIP'],
            'Typo3': ['typo3', 'typo3conf']
        }
        
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        self.phone_pattern = re.compile(
            r'(?:(?:\+|00)33|0)\s*[1-9](?:[\s.-]*\d{2}){4}'
        )
    
    def get_ip_address(self, domain):
        """Résoudre l'adresse IP"""
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def check_domain_online(self, domain):
        """Vérifier si le domaine est en ligne"""
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                if response.status_code < 500:
                    return True, url, response
            except:
                continue
        return False, None, None
    
    def detect_cms(self, html_content, headers):
        """Détecter le CMS"""
        detected_cms = []
        html_lower = html_content.lower()
        
        for cms, signatures in self.cms_signatures.items():
            for signature in signatures:
                if signature.lower() in html_lower:
                    detected_cms.append(cms)
                    break
        
        return detected_cms if detected_cms else ['Unknown']
    
    def detect_technologies(self, html_content, headers):
        """Détecter les technologies"""
        technologies = []
        html_lower = html_content.lower()
        
        js_frameworks = {
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', 'vue.min.js', '__vue__'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Tailwind': ['tailwind'],
        }
        
        for tech, signatures in js_frameworks.items():
            for sig in signatures:
                if sig in html_lower:
                    technologies.append(tech)
                    break
        
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        if 'cloudflare' in str(headers).lower():
            technologies.append('Cloudflare')
        
        return technologies if technologies else ['Unknown']
    
    def extract_title(self, html_content):
        """Extraire le titre de la page"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()
            
            # Essayer og:title
            og_title = soup.find('meta', property='og:title')
            if og_title and og_title.get('content'):
                return og_title['content'].strip()
            
            return ''
        except:
            return ''
    
    def extract_keywords(self, html_content):
        """Extraire les mots-clés"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            keywords = []
            
            # Meta keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and meta_keywords.get('content'):
                keywords.extend([k.strip() for k in meta_keywords['content'].split(',')])
            
            # Meta description (comme source de mots-clés)
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                desc = meta_desc['content']
                # Extraire les mots significatifs (plus de 4 caractères)
                words = re.findall(r'\b\w{5,}\b', desc.lower())
                keywords.extend(words[:10])
            
            # H1 tags
            h1_tags = soup.find_all('h1')
            for h1 in h1_tags[:3]:
                words = re.findall(r'\b\w{5,}\b', h1.get_text().lower())
                keywords.extend(words)
            
            # Nettoyer et dédupliquer
            keywords = list(dict.fromkeys([k for k in keywords if len(k) > 3]))
            return keywords[:20]  # Limiter à 20 mots-clés
        except:
            return []
    
    def extract_emails(self, html_content):
        """Extraire les emails"""
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text()
        emails = self.email_pattern.findall(text)
        
        valid_emails = []
        invalid_patterns = [
            'example.com', 'test.com', 'domain.com', 'yoursite.com',
            'sentry.io', 'wixpress.com', 'w.org', 'schema.org'
        ]
        
        for email in emails:
            email_lower = email.lower()
            if not any(pattern in email_lower for pattern in invalid_patterns):
                if email not in valid_emails:
                    valid_emails.append(email)
        
        return valid_emails[:5]
    
    def extract_phones(self, html_content):
        """Extraire les téléphones"""
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text()
        phones = self.phone_pattern.findall(text)
        
        cleaned_phones = []
        for phone in phones:
            cleaned = re.sub(r'[\s.-]', '', phone)
            if cleaned not in cleaned_phones:
                cleaned_phones.append(cleaned)
        
        return cleaned_phones[:5]
    
    def analyze_domain(self, domain):
        """Analyser complètement un domaine"""
        result = {
            'domain': domain,
            'online': False,
            'ip': None,
            'url': None,
            'title': '',
            'keywords': [],
            'cms': [],
            'technologies': [],
            'emails': [],
            'phones': [],
            'status_code': None,
            'error': None
        }
        
        try:
            result['ip'] = self.get_ip_address(domain)
            is_online, url, response = self.check_domain_online(domain)
            
            if not is_online:
                result['error'] = 'Domain not reachable'
                return result
            
            result['online'] = True
            result['url'] = url
            result['status_code'] = response.status_code
            
            html_content = response.text
            headers = response.headers
            
            result['title'] = self.extract_title(html_content)
            result['keywords'] = self.extract_keywords(html_content)
            result['cms'] = self.detect_cms(html_content, headers)
            result['technologies'] = self.detect_technologies(html_content, headers)
            result['emails'] = self.extract_emails(html_content)
            result['phones'] = self.extract_phones(html_content)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_domains_batch(self, domains, max_workers=10, progress_callback=None):
        """Analyser plusieurs domaines en parallèle"""
        results = []
        total = len(domains)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(self.analyze_domain, domain): domain 
                for domain in domains
            }
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total, result)
                    
                except Exception as e:
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total, None)
        
        return results


def generate_domain_hash(domain):
    """Générer un hash unique pour un domaine"""
    return hashlib.md5(domain.encode()).hexdigest()

