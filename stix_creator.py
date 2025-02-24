import json
import requests
from stix2 import Identity, Indicator, Bundle
from datetime import datetime, timedelta
import uuid
import csv
from io import StringIO
import yaml
import logging

class ThreatIntelCollector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        
    def fetch_data_from_url(self, url):
        """
        URL'den veri çeker ve format türüne göre parse eder
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            
            if 'json' in content_type:
                return self._parse_json(response.text)
            elif 'csv' in content_type or url.endswith('.csv'):
                return self._parse_csv(response.text)
            elif 'yaml' in content_type or url.endswith('.yml'):
                return self._parse_yaml(response.text)
            else:
                return self._parse_plain_text(response.text)
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"URL'den veri çekerken hata: {url} - {str(e)}")
            return None

    def _parse_json(self, content):
        """JSON formatındaki veriyi parse eder"""
        try:
            data = json.loads(content)
            return self._extract_ip_info(data)
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse hatası: {str(e)}")
            return None

    def _parse_csv(self, content):
        """CSV formatındaki veriyi parse eder"""
        try:
            ip_info = {}
            csv_file = StringIO(content)
            reader = csv.DictReader(csv_file)
            
            for row in reader:
                if 'ip' in row:
                    ip = row.pop('ip')
                    ip_info[ip] = self._format_details(row)
                    
            return ip_info
        except Exception as e:
            self.logger.error(f"CSV parse hatası: {str(e)}")
            return None

    def _parse_yaml(self, content):
        """YAML formatındaki veriyi parse eder"""
        try:
            data = yaml.safe_load(content)
            return self._extract_ip_info(data)
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parse hatası: {str(e)}")
            return None

    def _parse_plain_text(self, content):
        """Düz metin formatındaki veriyi parse eder"""
        ip_info = {}
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                ip_info[line] = {
                    'description': 'IP from plaintext list',
                    'confidence': 50,
                    'source': 'plain-text-list'
                }
        return ip_info

    def _extract_ip_info(self, data):
        """Farklı veri yapılarından IP bilgilerini çıkarır"""
        ip_info = {}
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'ip' in item:
                    ip = item.pop('ip')
                    ip_info[ip] = self._format_details(item)
        elif isinstance(data, dict):
            if 'ip_addresses' in data:
                for ip_data in data['ip_addresses']:
                    if isinstance(ip_data, dict) and 'ip' in ip_data:
                        ip = ip_data.pop('ip')
                        ip_info[ip] = self._format_details(ip_data)
                        
        return ip_info

    def _format_details(self, data):
        """IP detaylarını standart formata dönüştürür"""
        return {
            'description': data.get('description', 'No description provided'),
            'labels': data.get('labels', []).split(',') if isinstance(data.get('labels'), str) else data.get('labels', ['unknown']),
            'confidence': int(data.get('confidence', 50)),
            'detected_actions': data.get('detected_actions', []),
            'source': data.get('source', 'external-feed'),
            'category': data.get('category', 'unknown')
        }

    def create_stix_bundle(self, urls):
        """
        URL listesinden STIX 2.1 bundle oluşturur
        """
        identity = Identity(
            id="identity--" + str(uuid.uuid4()),
            name="Automated Threat Intel Feed",
            identity_class="organization"
        )
        
        indicators = []
        all_ip_info = {}
        
        # Tüm URL'lerden veri topla
        for url in urls:
            ip_info = self.fetch_data_from_url(url)
            if ip_info:
                all_ip_info.update(ip_info)
        
        # Her IP için indicator oluştur
        for ip, details in all_ip_info.items():
            valid_until = datetime.now() + timedelta(days=30)
            pattern = f"[ipv4-addr:value = '{ip}']"
            
            indicator = Indicator(
                id="indicator--" + str(uuid.uuid4()),
                created_by_ref=identity.id,
                name=f"Malicious IP: {ip}",
                description=details['description'],
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(),
                valid_until=valid_until,
                labels=details['labels'],
                confidence=details['confidence'],
                custom_properties={
                    "x_detected_actions": details['detected_actions'],
                    "x_source": details['source'],
                    "x_category": details['category']
                }
            )
            indicators.append(indicator)
        
        return Bundle(objects=[identity] + indicators)

def main(urls, output_file="threat_intel.json"):
    """
    Ana çalıştırma fonksiyonu
    """
    collector = ThreatIntelCollector()
    bundle = collector.create_stix_bundle(urls)
    
    with open(output_file, 'w') as f:
        json.dump(bundle.serialize(), f, indent=4)
    
    return output_file

# GitHub Actions için örnek kullanım
if __name__ == "__main__":
    import os
    
    # URL'leri environment variable'dan al
    urls = os.getenv('THREAT_INTEL_URLS', '').split(',')
    output_file = os.getenv('OUTPUT_FILE', 'threat_intel.json')
    
    if urls and urls[0]:  # Boş string kontrolü
        main(urls, output_file)
    else:
        print("No URLs provided in THREAT_INTEL_URLS environment variable")
