# bom_manager.py
import re
import requests
from bs4 import BeautifulSoup
from pathlib import Path


class BOMManager:
    
    def __init__(self, dropwiz_bom_folder_path, oci_bom_folder_path):
        self.dropwizard_bom_folder_path = dropwiz_bom_folder_path
        self.oci_bom_folder_path = oci_bom_folder_path
        
        self.dropwizard_bom_artifactory_link = 'https://artifactory.oci.oraclecorp.com/libs-release/com/oracle/pic/commons/dropwizard-service-bom/'
        self.oci_bom_artifactory_link = 'https://artifactory.oci.oraclecorp.com/libs-release/com/oracle/pic/sfw/oci-internal-bom/'
        
        self.dropwizard_bom_versions = self.get_artifactory_versions(self.dropwizard_bom_artifactory_link)
        self.oci_bom_versions = self.get_artifactory_versions(self.oci_bom_artifactory_link)
    
    def get_drop_wizard_bom_versions(self):
        return self.dropwizard_bom_versions
    
    def get_pci_bom_versions(self):
        return self.oci_bom_versions

    def get_artifactory_versions(self, url: str):
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract hrefs like "2.0.71/"
        versions = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.endswith("/") and href != "../":
                version = href.strip("/").strip()
                if re.match(r"^[\w\.\-\+]+$", version):
                    versions.append(version)

        # Sort versions numerically where possible
        versions = sorted(versions, key=lambda v: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', v)])
        return versions
    
    
    # def get_dropwizard_bom_versions(self):
    #     versions = self.get_artifactory_versions('https://artifactory.oci.oraclecorp.com/libs-release/com/oracle/pic/commons/dropwizard-service-bom/')
    #     return versions
    
    
    def download_bom_file(self, bom:str, version):

        if bom == 'dropwizard':
            url = f"{self.dropwizard_bom_artifactory_link.rstrip('/')}/{version}/dropwizard-service-bom-{version}.pom"
            output_path = Path(self.dropwizard_bom_folder_path) / f"dropwizard-service-bom-{version}.xml"
            dropwizard_dir = Path(self.dropwizard_bom_folder_path)
            dropwizard_dir.mkdir(parents=True, exist_ok=True)
        elif bom == 'oci':
            url = f"{self.oci_bom_artifactory_link.rstrip('/')}/{version}/oci-internal-bom-{version}.pom"
            output_path = Path(self.oci_bom_folder_path) / f"oci-internal-bom-{version}.xml"
            oci_dir = Path(self.oci_bom_folder_path)
            oci_dir.mkdir(parents=True, exist_ok=True)
        else:
            print("Incorrect bom value, not Found")

        print(f"Url : {url}")
        
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            output_path.write_bytes(response.content)
            print(f"Successfully downloaded {bom} bom with version {version}")
            return output_path
        else:
            print(f"{bom} bom download failed with status {response.status_code}: {response.text[:200]}")
            return None
        
