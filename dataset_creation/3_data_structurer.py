#!/usr/bin/env python3

import json
import logging
import pandas as pd
import yaml
import requests
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime
import re
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataStructurer:
    def __init__(self, input_dir: str = "filtered_data", output_dir: str = "structured_data", ollama_model: str = "gemma:2b", ollama_port: int = 11434):
        """Initialize the data structurer with directory configurations."""
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ollama_model = ollama_model
        self.ollama_url = f"http://localhost:{ollama_port}/api/generate"
        
        # Verify Ollama connection
        if not self._verify_ollama_connection():
            logger.error(f"Could not connect to Ollama at {self.ollama_url}")
            raise ConnectionError(f"Could not connect to Ollama at {self.ollama_url}")
        
        # Template patterns for different data types
        self.templates = {
            'vulnerability': {
                'system_prompt': """You are a cybersecurity expert. Analyze the following vulnerability data and create a detailed, technical response.
                Focus on technical details, impact, and mitigation strategies. Format your response in a clear, structured way.""",
                'instruction': [
                    "Explain the {cve_id} vulnerability and its potential impact.",
                    "What are the security implications of {cve_id}?",
                    "Describe the vulnerability identified as {cve_id}.",
                    "How does the {cve_id} vulnerability affect system security?"
                ]
            },
            'attack_pattern': {
                'system_prompt': """You are a cybersecurity expert. Analyze the following attack pattern data and create a detailed, technical response.
                Focus on attack methodology, techniques used, and defense strategies. Format your response in a clear, structured way.""",
                'instruction': [
                    "How does the {attack_name} attack work?",
                    "Explain the methodology of {attack_name}.",
                    "What is the {attack_name} attack pattern?",
                    "Describe the execution of {attack_name} attack."
                ]
            },
            'security_advisory': {
                'system_prompt': """You are a cybersecurity expert. Analyze the following security advisory data and create a detailed, technical response.
                Focus on the security implications, recommended actions, and implementation details. Format your response in a clear, structured way.""",
                'instruction': [
                    "What are the recommended actions for {advisory_id}?",
                    "Explain the security advisory {advisory_id}.",
                    "What measures should be taken regarding {advisory_id}?",
                    "Describe the security implications and fixes for {advisory_id}."
                ]
            }
        }

    def _verify_ollama_connection(self) -> bool:
        """Verify connection to Ollama API."""
        try:
            response = requests.get(self.ollama_url.replace('/generate', '/version'), timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error connecting to Ollama: {str(e)}")
            return False

    def call_ollama(self, prompt: str, system_prompt: str, max_retries: int = 2) -> Optional[str]:
        """Call Ollama API with retry mechanism."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.ollama_url,
                    json={
                        "model": self.ollama_model,
                        "prompt": prompt,
                        "system": system_prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.7,
                            "num_predict": 256  # Limit response length
                        }
                    },
                    timeout=120  # Reduced timeout
                )
                response.raise_for_status()
                return response.json()["response"]
            except requests.exceptions.Timeout:
                logger.warning(f"Attempt {attempt + 1} timed out after 15 seconds")
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
            except Exception as e:
                logger.warning(f"Unexpected error in attempt {attempt + 1}: {str(e)}")
            
            if attempt < max_retries - 1:
                time.sleep(1)  # Shorter backoff
                continue
        return None

    def load_data(self, file_path: Path) -> Union[Dict, List, None]:
        """Load data from various file formats."""
        try:
            suffix = file_path.suffix.lower()
            if suffix == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            elif suffix in {'.yaml', '.yml'}:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            elif suffix == '.csv':
                return pd.read_csv(file_path).to_dict('records')
            else:
                logger.warning(f"Unsupported file format: {suffix}")
                return None
        except Exception as e:
            logger.error(f"Error loading file {file_path}: {str(e)}")
            return None

    def detect_entry_type(self, entry: Dict) -> Optional[str]:
        """Detect the type of cybersecurity data entry."""
        # Check for CVE pattern
        if any(key.lower().startswith('cve-') for key in entry.keys()) or \
           any('cve-' in str(value).lower() for value in entry.values()):
            return 'vulnerability'
        
        # Check for attack pattern indicators
        if any(key in entry for key in {'attack_pattern', 'technique', 'tactic'}) or \
           any('attack' in str(value).lower() for value in entry.values()):
            return 'attack_pattern'
        
        # Check for security advisory
        if any(key in entry for key in {'advisory', 'bulletin', 'notice'}) or \
           any(isinstance(value, str) and 'advisory' in value.lower() for value in entry.values()):
            return 'security_advisory'
        
        return None

    def extract_fields(self, entry: Dict, entry_type: str) -> Dict:
        """Extract relevant fields based on entry type."""
        fields = {}
        
        if entry_type == 'vulnerability':
            # Extract CVE ID
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_matches = []
            for value in entry.values():
                if isinstance(value, str):
                    matches = re.findall(cve_pattern, value, re.IGNORECASE)
                    cve_matches.extend(matches)
            
            fields['cve_id'] = cve_matches[0] if cve_matches else "Unknown CVE"
            fields['raw_data'] = json.dumps(entry, indent=2)
            
        elif entry_type == 'attack_pattern':
            fields['attack_name'] = self._find_field(entry, ['name', 'title', 'pattern_name'])
            fields['raw_data'] = json.dumps(entry, indent=2)
            
        elif entry_type == 'security_advisory':
            fields['advisory_id'] = self._find_field(entry, ['id', 'advisory_id', 'bulletin_id'])
            fields['raw_data'] = json.dumps(entry, indent=2)
        
        return fields

    def _find_field(self, entry: Dict, possible_keys: List[str]) -> str:
        """Helper method to find a field value from possible keys."""
        for key in possible_keys:
            for entry_key, value in entry.items():
                if key.lower() in entry_key.lower() and isinstance(value, str):
                    return value
        return "Information not available"

    def create_instruction_response_pair(self, entry: Dict, entry_type: str) -> List[Dict]:
        """Create instruction-response pairs from an entry using Ollama."""
        fields = self.extract_fields(entry, entry_type)
        template = self.templates[entry_type]
        pairs = []
        
        # Only use the first two instruction templates to reduce processing time
        for instruction_template in template['instruction'][:2]:
            instruction = instruction_template.format(**fields)
            
            # Create a focused prompt for Ollama with just the relevant entry data
            prompt = f"""Analyze this {entry_type} and answer: {instruction}
            
            Data: {json.dumps(entry, indent=2)}"""
            
            response = self.call_ollama(prompt, template['system_prompt'])
            if response:
                pairs.append({
                    'instruction': instruction,
                    'response': response,
                    'type': entry_type,
                    'source_data': {
                        'id': fields.get('cve_id', fields.get('attack_name', fields.get('advisory_id', 'Unknown'))),
                        'type': entry_type
                    }
                })
        
        return pairs

    def structure_dataset(self, input_file: Path) -> List[Dict]:
        """Structure the dataset into instruction-response format."""
        data = self.load_data(input_file)
        if not data:
            return []
        
        # Ensure data is a list
        if isinstance(data, dict):
            data = [data]
        
        structured_pairs = []
        total_entries = len(data)
        
        # Process only first 5 entries for testing
        for i, entry in enumerate(data[:9999], 1):
            logger.info(f"Processing entry {i}/{min(5, total_entries)} from {input_file.name}")
            entry_type = self.detect_entry_type(entry)
            if entry_type:
                pairs = self.create_instruction_response_pair(entry, entry_type)
                if pairs:
                    structured_pairs.extend(pairs)
                    logger.info(f"Generated {len(pairs)} instruction-response pairs for entry {i}")
                else:
                    logger.warning(f"No instruction-response pairs generated for entry {i}")
            else:
                logger.warning(f"Could not determine type for entry {i}")
        
        return structured_pairs

    def process_directory(self):
        """Process all files in the input directory and save as a single consolidated JSON file."""
        all_structured_pairs = []
        total_pairs = 0
        processed_files = 0
        
        # Get all JSON files in the input directory
        input_files = list(self.input_dir.glob('*_filtered_*.json'))
        total_files = len(input_files)
        
        # Process only first 2 files for testing
        for i, file_path in enumerate(input_files[:9999], 1):
            logger.info(f"Processing file {i}/{min(2, total_files)}: {file_path.name}")
            structured_pairs = self.structure_dataset(file_path)
            
            if structured_pairs:
                processed_files += 1
                total_pairs += len(structured_pairs)
                all_structured_pairs.extend(structured_pairs)
                logger.info(f"Generated {len(structured_pairs)} pairs from {file_path.name}")
        
        # Save all data in a single consolidated JSON file
        if all_structured_pairs:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"consolidated_cybersecurity_dataset_{timestamp}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'metadata': {
                        'total_entries': len(all_structured_pairs),
                        'processed_files': processed_files,
                        'generation_timestamp': timestamp,
                        'model_used': self.ollama_model
                    },
                    'data': all_structured_pairs
                }, f, indent=2)
            
            logger.info(f"Saved consolidated dataset to {output_file}")
        
        logger.info("Structuring Statistics:")
        logger.info(f"Processed Files: {processed_files}")
        logger.info(f"Total Instruction-Response Pairs: {total_pairs}")

def main():
    """Main function to demonstrate usage."""
    try:
        structurer = CyberDataStructurer(ollama_port=11434)  # Use the default port
        structurer.process_directory()
    except ConnectionError as e:
        logger.error(f"Failed to initialize: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 