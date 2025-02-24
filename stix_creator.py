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
            self.logger.info(f"Fetching data from URL: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            
            if 'json' in content_type or url.endswith('.json'):
                return self._parse_json(response.text)
            elif 'csv' in content_type or url.endswith('.csv'):
                return self._parse_csv(response.text)
            elif 'yaml' in content_type or url.endswith('.yml') or url.endswith('.yaml'):
                return self._parse_yaml(response.text)
            else:
                return self._parse_plain_text(response.text)
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching data from URL: {url} - {str(e)}")
            return {}

    def _parse_json(self, content):
        """JSON formatındaki veriyi parse eder"""
        try:
            data = json.loads(content)
            return self._extract_ip_info(data)
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse error: {str(e)}")
            return {}

    def _parse_csv(self, content):
        """CSV formatındaki veriyi parse eder"""
        try:
            ip_info = {}
            csv_file = StringIO(content)
            reader = csv.DictReader(csv_file)
            
            for row in reader:
                # IP sütunu için alternatif isimler kontrol et
                ip_field = next((field for field in ['ip', 'IP', 'ip_address', 'address', 'host'] 
                               if field in row), None)
                
                if ip_field:
                    ip = row.pop(ip_field)
                    ip_info[ip] = self._format_details(row)
                else:
                    self.logger.warning("CSV row missing IP field")
                    
            return ip_info
        except Exception as e:
            self.logger.error(f"CSV parse error: {str(e)}")
            return {}

    def _parse_yaml(self, content):
        """YAML formatındaki veriyi parse eder"""
        try:
            data = yaml.safe_load(content)
            return self._extract_ip_info(data)
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parse error: {str(e)}")
            return {}

    def _parse_plain_text(self, content):
        """Düz metin formatındaki veriyi parse eder"""
        ip_info = {}
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                ip_info[line] = self._format_details({})
        return ip_info

    def _extract_ip_info(self, data):
        """Farklı veri yapılarından IP bilgilerini çıkarır"""
        ip_info = {}
        
        try:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        # IP için alternatif alanları kontrol et
                        ip_field = next((field for field in ['ip', 'IP', 'ip_address', 'address'] 
                                    if field in item), None)
                        if ip_field:
                            ip = item.pop(ip_field)
                            ip_info[ip] = self._format_details(item)
                            
            elif isinstance(data, dict):
                # Farklı veri yapıları için kontroller
                if 'ip_addresses' in data and isinstance(data['ip_addresses'], list):
                    for ip_data in data['ip_addresses']:
                        if isinstance(ip_data, dict):
                            ip_field = next((field for field in ['ip', 'IP', 'ip_address', 'address'] 
                                        if field in ip_data), None)
                            if ip_field:
                                ip = ip_data.pop(ip_field)
                                ip_info[ip] = self._format_details(ip_data)
                                
                elif 'data' in data and isinstance(data['data'], list):
                    return self._extract_ip_info(data['data'])
                    
        except Exception as e:
            self.logger.error(f"Error extracting IP info: {str(e)}")
            
        return ip_info

    def _format_details(self, data):
        """IP detaylarını standart formata dönüştürür"""
        if data is None:
            data = {}
            
        # Varsayılan değerler sözlüğü
        default_details = {
            'description': 'No description provided',
            'labels': ['unknown'],
            'confidence': 50,
            'detected_actions': [],
            'source': 'external-feed',
            'category': 'unknown'
        }
        
        try:
            # Labels işleme
            if 'labels' in data:
                if isinstance(data['labels'], str):
                    labels = [label.strip() for label in data['labels'].split(',')]
                elif isinstance(data['labels'], list):
                    labels = data['labels']
                else:
                    labels = default_details['labels']
            else:
                labels = default_details['labels']

            # Confidence değerini sayıya çevirme
            try:
                confidence = int(data.get('confidence', default_details['confidence']))
                confidence = max(0, min(100, confidence))  # 0-100 aralığında sınırla
            except (ValueError, TypeError):
                confidence = default_details['confidence']

            # Detected actions işleme
            detected_actions = data.get('detected_actions', default_details['detected_actions'])
            if isinstance(detected_actions, str):
                detected_actions = [act.strip() for act in detected_actions.split(',')]
            elif not isinstance(detected_actions, list):
                detected_actions = default_details['detected_actions']

            return {
                'description': str(data.get('description', default_details['description'])),
                'labels': labels,
                'confidence': confidence,
                'detected_actions': detected_actions,
                'source': str(data.get('source', default_details['source'])),
                'category': str(data.get('category', default_details['category']))
            }
            
        except Exception as e:
            self.logger.error(f"Error formatting details: {str(e)}")
            return default_details

    def create_stix_bundle(self, urls):
        """URL listesinden STIX 2.1 bundle oluşturur"""
        identity = Identity(
            id="identity--" + str(uuid.uuid4()),
            name="Automated Threat Intel Feed",
            identity_class="organization"
        )
        
        indicators = []
        all_ip_info = {}
        
        # URL listesini kontrol et
        if isinstance(urls, str):
            urls = [url.strip() for url in urls.split(',')]
        
        # Tüm URL'lerden veri topla
        for url in urls:
            if url:  # Boş URL kontrolü
                self.logger.info(f"Processing URL: {url}")
                ip_info = self.fetch_data_from_url(url)
                if ip_info:
                    all_ip_info.update(ip_info)
                else:
                    self.logger.warning(f"No data retrieved from URL: {url}")
        
        # Her IP için indicator oluştur
        for ip, details in all_ip_info.items():
            try:
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
                self.logger.info(f"Created indicator for IP: {ip}")
                
            except Exception as e:
                self.logger.error(f"Error creating indicator for IP {ip}: {str(e)}")
                continue
        
        return Bundle(objects=[identity] + indicators)

def main(urls, output_file="threat_intel.json"):
    """Ana çalıştırma fonksiyonu"""
    collector = ThreatIntelCollector()
    bundle = collector.create_stix_bundle(urls)
    
    try:
        with open(output_file, 'w') as f:
            json.dump(bundle.serialize(), f, indent=4)
        logging.info(f"Successfully wrote bundle to {output_file}")
        return output_file
    except Exception as e:
        logging.error(f"Error writing bundle to file: {str(e)}")
        return None

if __name__ == "__main__":
    import os
    
    # Environment variables'dan URL'leri al
    urls = os.getenv('THREAT_INTEL_URLS', '')
    output_file = os.getenv('OUTPUT_FILE', 'threat_intel.json')
    
    if urls:
        main(urls, output_file)
    else:
        print("No URLs provided in THREAT_INTEL_URLS environment variable")
