import json
import os
from pathlib import Path
from typing import List
import xml.etree.ElementTree as ET
from services.pom_parser import PomParser
from services.bom_manager import BOMManager
import re
from packaging import version


BASE_DIR_PATH = "/Users/ansmaury/Desktop/hackathon26/osa/"
PARENT_MODULE = "/Users/ansmaury/Desktop/hackathon26/osa/personalization-service"
VULNERABILITY_JSON_PATH = "/Users/ansmaury/Desktop/hackathon26/osa/uploads/vulnerability_input.json"
DROPWIZARD_BOM_FOLDER_PATH = "/Users/ansmaury/Desktop/hackathon26/osa/dropwizard_boms"
OCI_BOM_FOLDER_PATH = "/Users/ansmaury/Desktop/hackathon26/osa/oci_boms"
variable_pattern = r'^\$\{([^{}]*)\}$'
version_pattern = r'^\d+(?:\.\d+)+$'

def load_vulnerabilities(vuln_file):
    with open(vuln_file) as f:
        data = json.load(f)
    if 'scanReport' in data:
        data = data['scanReport']
        if 'findings' in data:
            return data['findings']
    return None

def find_pom(module):
    parent_path = Path(BASE_DIR_PATH)
    if not parent_path.is_dir():
        print(f"Error: Base directory path '{BASE_DIR_PATH}' does not exist.")
        return None

    found_module = []
    for sub_dir in parent_path.rglob(module):
        # Check if the pom.xml file exists within that subdirectory
        if (sub_dir / "pom.xml").is_file():
            found_module.append(sub_dir)
            
    return found_module

def find_parent_poms(start_path_str, base_path_str):
    start_path = Path(start_path_str).resolve()
    base_path = Path(base_path_str).resolve()
    
    # if not start_path.is_relative_to(base_path):
    #     print("Start path is not a child of the base path.")
    #     return []

    maven_projects = []
    # Path.parents is a sequence of all parent directories
    for parent_dir in start_path.parents:
        if parent_dir == base_path:
            # Check the base path itself for a pom.xml before stopping
            if (base_path / "pom.xml").is_file():
                maven_projects.append(base_path)
            break
        
        # Check for pom.xml in the current parent directory
        if (parent_dir / "pom.xml").is_file():
            maven_projects.append(parent_dir)

    # Reversing the list for an intuitive "root-first" order
    return maven_projects[::-1]


def update_dependency(pomParser: PomParser, dependency, vuln, module):
    # Check if it is a version or property and update accordingly
    if dependency['version'] != '':
        is_property = re.fullmatch(variable_pattern, dependency['version'])
        is_version = re.fullmatch(version_pattern, dependency['version'])
        if is_property:
            return update_property(pomParser, dependency, vuln, module, is_property.group(1))
        elif is_version:
            pomParser.update_dependency_version(dependency['groupId'], dependency['artifactId'], vuln['CVE_Fix_Version'])
            print(f"Dependency version updated of groupId {dependency['groupId']} and artifactId {dependency['artifactId']} from version {dependency['version']} --> {vuln['CVE_Fix_Version']} in module {module}")
            pomParser.save()
            return True
        else:
            print(f"Version {dependency['version']} of groupId {dependency['groupId']} and artifactId {dependency['artifactId']} has incorrect value")

        return False


def update_property(pomParser:PomParser, dependency, vuln, module, property_name):
    # check if current module define this property
    properties = pomParser.find_properties()
    if property_name in properties:
        pomParser.update_property(property_name, vuln['CVE_Fix_Version'])
        print(f"Property {property_name} updated from version {properties[property_name]} --> {vuln['CVE_Fix_Version']} in module {module}")
        pomParser.save()
        return True
    
    # Check dependency in parent pom files
    
    # Find parent pom modules
    parent_pom_modules = find_parent_poms(module, BASE_DIR_PATH)
    if len(parent_pom_modules) == 0:
        print("No parent modules found with pom files above module ", module)
        return False
    
    for parent_module in parent_pom_modules:
        parentPomParser = PomParser(parent_module / "pom.xml")
        parent_dependency = parentPomParser.find_dependency(vuln["Package_Name"])
        if parent_dependency is None:
            continue
        return update_dependency(parentPomParser, parent_dependency, vuln, parent_module)
    
    return False

def update_build_plugin_artifact(pomParser:PomParser, artifact_item, vuln, module):
    # Check if it is a version or property and update accordingly
    if artifact_item['version'] != '':
        is_property = re.fullmatch(variable_pattern, artifact_item['version'])
        is_version = re.fullmatch(version_pattern, artifact_item['version'])
        if is_property:
            return update_property(pomParser, artifact_item, vuln, module, is_property.group(1))
        elif is_version:
            pomParser.update_plugin_artifact_version(artifact_item['groupId'], artifact_item['artifactId'], vuln['CVE_Fix_Version'])
            print(f"Build configuration artifact version updated of groupId {artifact_item['groupId']} and artifactId {artifact_item['artifactId']} from version {artifact_item['version']} --> {vuln['CVE_Fix_Version']} in module {module}")
            pomParser.save()
            return True
        else:
            print(f"Version {artifact_item['version']} of groupId {artifact_item['groupId']} and artifactId {artifact_item['artifactId']} has incorrect value")

        return False

def check_and_update_bom_version(pomParser:PomParser, dependency, vuln, module):
    print('Hello! Updating BOM!')
    parent_pom_modules = find_parent_poms(module, BASE_DIR_PATH)
    if len(parent_pom_modules) == 0:
        print("No parent modules found with pom files above module ", module)
    
    for parent_module in parent_pom_modules:
        parentPomParser = PomParser(parent_module / "pom.xml")
        parent_dependency = parentPomParser.find_dependency(vuln["Package_Name"])
        if parent_dependency is None:
            is_updated = False
            continue
        if 'version' in parent_dependency and parent_dependency['version'] is not None:
            return update_dependency(parentPomParser, parent_dependency, vuln, parent_module)

    # Here depdendency is managed by bom
    bom_dependency = pomParser.find_dependency("dropwizard-service-bom")
    if bom_dependency is not None:
        is_updated = update_bom_version(pomParser, bom_dependency, vuln, module)
        
    if not is_updated:
        for parent_module in parent_pom_modules:
            parentPomParser = PomParser(parent_module / "pom.xml")
            bom_dependency = parentPomParser.find_dependency("dropwizard-service-bom")
            if bom_dependency is not None:
                is_updated = update_bom_version(parentPomParser, bom_dependency, vuln, parent_module)

            if is_updated:
                break
    
    if not is_updated:
        for parent_module in parent_pom_modules:
            parentPomParser = PomParser(parent_module / "pom.xml")
            bom_dependency = parentPomParser.find_dependency("oci-internal-bom")
            if bom_dependency is not None:
                is_updated = update_bom_version(parentPomParser, bom_dependency, vuln, parent_module)

            if is_updated:
                break

def update_bom_version(pomParser:PomParser, bom_dependency, vuln, module):
    bomManager = BOMManager(DROPWIZARD_BOM_FOLDER_PATH, OCI_BOM_FOLDER_PATH)

    is_property = re.fullmatch(variable_pattern, bom_dependency['version'])
    is_version = re.fullmatch(version_pattern, bom_dependency['version'])

    if is_version:
        bom_version = bom_dependency['version']

    elif is_property:
        properties = pomParser.find_properties()
        property_name = is_property.group(1)
        if property_name in properties:
            bom_version = properties[property_name]
    else:
        print(f"{bom_dependency['artifactId']} with version {bom_dependency['version']} is invalid")
        return False
    
    # Dropwizard update
    if bom_dependency['artifactId'] == 'dropwizard-service-bom':
        # bom_index = bomManager.dropwizard_bom_versions.index(bom_version)
        bom_index = len(bomManager.dropwizard_bom_versions)-1
        if(bom_index >= len(bomManager.dropwizard_bom_versions)):
            print(f"Dropwizard bom version is already updated to latest value {bom_version}")

        bom_folder_path = Path(bomManager.dropwizard_bom_folder_path).resolve()
        while(bom_index >= bomManager.dropwizard_bom_versions.index(bom_version)):
            drop_wizard_version = bomManager.dropwizard_bom_versions[bom_index]
            
            if not (bom_folder_path / f"dropwizard-service-bom-{drop_wizard_version}.xml").is_file():    
                bomManager.download_bom_file('dropwizard', drop_wizard_version)

            if (bom_folder_path / f"dropwizard-service-bom-{drop_wizard_version}.xml").is_file():
                bom_parser = PomParser(bom_folder_path / f"dropwizard-service-bom-{drop_wizard_version}.xml")
                vuln_dependency = bom_parser.find_dependency(vuln['Package_Name'])
                if vuln_dependency is not None:
                    if 'version' in vuln_dependency and vuln_dependency['version'] is not None:
                        is_property = re.fullmatch(variable_pattern, vuln_dependency['version'])
                        is_version = re.fullmatch(version_pattern, vuln_dependency['version'])
                        if is_version:
                            vuln_bom_version = vuln_dependency['version']
                        elif is_property:
                            properties = bom_parser.find_properties()
                            if is_property.group(1) in properties:
                                vuln_bom_version = properties[is_property.group(1)]
                        else:
                            print("Dependency version in dropwizard is not valid")

                    if version.parse(vuln_bom_version) >= version.parse(vuln['CVE_Fix_Version']):
                        drop_vuln = bom_dependency.copy()
                        drop_vuln['CVE_Fix_Version'] = drop_wizard_version
                        print('hrllo2!')
                        return update_dependency(pomParser, bom_dependency, drop_vuln, module)                
                    
            bom_index = bom_index - 1      
    
    elif bom_dependency['artifactId'] == 'oci-internal-bom':
        # bom_index = bomManager.oci_bom_versions.index(bom_version)
        bom_index = len(bomManager.oci_bom_versions) - 1
        if(bom_index >= len(bomManager.oci_bom_versions)):
            print(f"Dependency version {vuln_dependency['version']} in oci bom is not valid for artifact {vuln_dependency['artifactId']}")

        bom_folder_path = Path(bomManager.oci_bom_folder_path).resolve()
        while(bom_index >= bomManager.oci_bom_versions.index(bom_version)):
            oci_internal_version = bomManager.oci_bom_versions[bom_index]
            
            if not (bom_folder_path / f"oci-internal-bom-{oci_internal_version}.xml").is_file():    
                bomManager.download_bom_file('oci', oci_internal_version)

            if (bom_folder_path / f"oci-internal-bom-{oci_internal_version}.xml").is_file():
                bom_parser = PomParser(bom_folder_path / f"oci-internal-bom-{oci_internal_version}.xml")
                vuln_dependency = bom_parser.find_dependency(vuln['Package_Name'])
                if vuln_dependency is not None:
                    if 'version' in vuln_dependency and vuln_dependency['version'] is not None:
                        is_property = re.fullmatch(variable_pattern, vuln_dependency['version'])
                        is_version = re.fullmatch(version_pattern, vuln_dependency['version'])
                        if is_version:
                            vuln_bom_version = vuln_dependency['version']
                        elif is_property:
                            properties = bom_parser.find_properties()
                            if is_property.group(1) in properties:
                                vuln_bom_version = properties[is_property.group(1)]
                        else:
                            print(f"Dependency version {vuln_dependency['version']} in oci bom is not valid for artifact {vuln_dependency['artifactId']}")

                    if version.parse(vuln_bom_version) >= version.parse(vuln['CVE_Fix_Version']):
                        oci_vuln = bom_dependency.copy()
                        oci_vuln['CVE_Fix_Version'] = oci_internal_version
                        return update_dependency(pomParser, bom_dependency, oci_vuln, module)                
                    
            bom_index = bom_index - 1       
    
    return False


def remediate_vulnerabilities():
    vulnerability_data = load_vulnerabilities(VULNERABILITY_JSON_PATH)

    if vulnerability_data is None or len(vulnerability_data) == 0:
        print("No vulnerability found in input file")
        return

    for vuln in vulnerability_data:
        if 'metadata' in vuln:
            vuln = vuln ['metadata']
        else:
            print(f"No metadata found for vuln {vuln['summary']}")

        print(f"Vulnerabiltiy - ArtifactId : {vuln['Package_Name']}, Fix Version : {vuln['CVE_Fix_Version']}, module : {vuln['Artifact_Name']}")
        vuln_module = find_pom(vuln['Artifact_Name'])
        for module in vuln_module:
            pomParser = PomParser(module / "pom.xml")

            # check if artifact is mentioned as dependency
            dependency = pomParser.find_dependency(vuln["Package_Name"])
            print(dependency)

            if dependency is None:
                print(f"No dependency found artifactId {vuln['Package_Name']} in the module {module}")
                is_updated = False
            else:            
                is_updated = update_dependency(pomParser, dependency, vuln, module)
            
            # Check if artifact dependency version is mentioned in build plugin configurations (for 3p non java libs)
            if not is_updated:
                build_artifact_item = pomParser.find_plugin_config(vuln["Package_Name"])

                if build_artifact_item is None:
                    print(f"No build configuraiton found for artifactId {vuln['Package_Name']} in the module {module}")
                else:
                    is_updated = update_build_plugin_artifact(pomParser, build_artifact_item, vuln, module)

            if not is_updated:
                check_and_update_bom_version(pomParser, dependency, vuln, module)

        print('Done')




def main():
    remediate_vulnerabilities()

if __name__ == "__main__":
    main()