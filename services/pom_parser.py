import re
import xml.etree.ElementTree as ET
from pathlib import Path

class PomParser:
    def __init__(self, pom_path):
        self.path = Path(pom_path)
        self.original_text = self.path.read_text(encoding='utf-8')
        self.tree = ET.ElementTree(ET.fromstring(self.original_text))
        self.root = self.tree.getroot()
        self.ns = self._detect_ns()

    def _detect_ns(self):
        if self.root.tag.startswith("{"):
            uri = self.root.tag.split("}")[0].strip("{")
            return {"ns": uri}
        return {}

    def _tag(self, name):
        return f"{{{self.ns['ns']}}}{name}" if self.ns else name


    def find_dependencies(self):
        deps = []
        for dep in self.root.findall(f".//{self._tag('dependency')}"):
            deps.append({
                "groupId": dep.findtext(self._tag("groupId")) or "",
                "artifactId": dep.findtext(self._tag("artifactId")) or "",
                "version": dep.findtext(self._tag("version")) or "",
            })
        return deps
    
    def find_dependency(self, artifactId):
        """Find and return a particular dependency matching groupId, artifactId"""

        deps = self.find_dependencies()

        for dep in deps:
            # if dep['groupId'] == groupId and dep['artifactId'] == artifactId:
            if dep['artifactId'] == artifactId:
                return dep
        
        return None

    def find_properties(self):
        props = {}
        props_elem = self.root.find(f".//{self._tag('properties')}")
        if props_elem is not None:
            for child in props_elem:
                props[child.tag.split("}")[-1]] = (child.text or "").strip()
        return props

    def find_plugin_configurations(self):
        configs = []
        for artifact_item in self.root.findall(
            f".//{self._tag('artifactItems')}/{self._tag('artifactItem')}"
        ):
            configs.append({
                "groupId": artifact_item.findtext(self._tag("groupId")) or "",
                "artifactId": artifact_item.findtext(self._tag("artifactId")) or "",
                "version": artifact_item.findtext(self._tag("version")) or "",
                "outputDirectory": artifact_item.findtext(self._tag("outputDirectory")) or "",
            })
        return configs
    
    def find_plugin_config(self, artifactId):

        build_configs = self.find_plugin_configurations()
        for artifact_item in build_configs:
            # if artifact_item['groupId'] == groupId and artifact_item['artifactId'] == artifactId:
            if artifact_item['artifactId'] == artifactId:    
                return artifact_item
            
        return None

    def update_dependency_version(self, group_id, artifact_id, new_version):
        """Update <version> of a dependency with minimal diff."""
        for dep in self.root.findall(f".//{self._tag('dependency')}"):
            gid = dep.findtext(self._tag('groupId'))
            aid = dep.findtext(self._tag('artifactId'))
            if gid == group_id and aid == artifact_id:
                old_version = dep.findtext(self._tag('version'))
                if old_version and old_version != new_version:
                    pattern = re.compile(
                        rf"(<groupId>\s*{re.escape(group_id)}\s*</groupId>.*?"
                        rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>.*?"
                        rf"<version>\s*){re.escape(old_version)}(\s*</version>)",
                        re.DOTALL
                    )
                    new_text, n = pattern.subn(rf"\g<1>{new_version}\g<2>", self.original_text, count=1)
                    if n:
                        self.original_text = new_text
                        return True
        return False

    def update_property(self, prop_name, new_value):
        """Update <prop_name>value</prop_name> with minimal diff."""
        pattern = re.compile(
            rf"(<{prop_name}>\s*)[^<]+(\s*</{prop_name}>)"
        )
        new_text, n = pattern.subn(rf"\g<1>{new_value}\g<2>", self.original_text, count=1)
        if n:
            self.original_text = new_text
            return True
        return False

    def update_plugin_artifact_version(self, group_id, artifact_id, new_version):
        """Update <version> inside plugin configuration artifactItem with minimal diff."""
        pattern = re.compile(
            rf"(<artifactItem>.*?<groupId>\s*{re.escape(group_id)}\s*</groupId>.*?"
            rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>.*?"
            rf"<version>\s*)[^<]+(\s*</version>.*?</artifactItem>)",
            re.DOTALL
        )
        new_text, n = pattern.subn(rf"\g<1>{new_version}\g<2>", self.original_text, count=1)
        if n:
            self.original_text = new_text
            return True
        return False

    def save(self, output_path=None):
        target = output_path or self.path
        target.write_text(self.original_text, encoding='utf-8')

