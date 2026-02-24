#!/usr/bin/env python3

import json
import logging
import yaml
import pandas as pd
from pathlib import Path
from typing import Dict, List, Union, Set, Tuple
from datetime import datetime
import re
import requests
import argparse
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataFilter:
    def __init__(self, input_dir: str = "raw_data", output_dir: str = "filtered_data", ollama_url: str = "http://localhost:11434"):
        """Initialize the data filter with input and output directory configurations."""
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ollama_url = ollama_url
        self.model = "gemma:2b"
        
        # Keywords and patterns for filtering
        self.cybersecurity_keywords = {
            'high_relevance': {
                'vulnerability', 'exploit', 'malware', 'ransomware', 'cyber', 'security',
                'attack', 'threat', 'breach', 'CVE-', 'patch', 'authentication', 'authorization',
                'encryption', 'cryptography', 'backdoor', 'botnet', 'phishing', 'injection',
                'zero-day', '0day', 'penetration', 'pentest', 'firewall', 'malicious'
            },
            'medium_relevance': {
                'network', 'system', 'software', 'hardware', 'protocol', 'server',
                'client', 'database', 'web', 'application', 'code', 'programming',
                'access', 'control', 'monitoring', 'detection', 'response', 'incident'
            }
        }
        
        # Patterns to identify low-quality or irrelevant entries
        self.exclusion_patterns = {
            'generic_terms': r'\b(test|sample|example|dummy|todo)\b',
            'placeholder_text': r'\b(lorem ipsum|xxx|placeholder)\b',
            'empty_content': r'^\s*$',
        }
        
        # Minimum content requirements
        self.min_content_length = 50  # characters
        self.min_keyword_matches = 2
        
        # Check if Ollama is available
        self.ollama_available = self.check_ollama_availability()
        if self.ollama_available:
            logger.info(f"Successfully connected to Ollama with model {self.model}")
        else:
            logger.warning("Could not connect to Ollama. Falling back to rule-based filtering.")

    def check_ollama_availability(self) -> bool:
        """Check if Ollama API is available"""
        try:
            response = requests.get(f"{self.ollama_url}/api/version")
            logger.info(f"Ollama API version response: {response.status_code}")
            if response.status_code == 200:
                # Also check if the model is available
                model_response = requests.get(
                    f"{self.ollama_url}/api/tags"
                )
                logger.info(f"Ollama API tags response: {model_response.status_code}")
                if model_response.status_code == 200:
                    available_models = model_response.json().get("models", [])
                    # Model names might include tags like :latest
                    model_names = []
                    for model in available_models:
                        full_name = model.get("name", "")
                        model_names.append(full_name)
                        # Also add base name without tag
                        if ":" in full_name:
                            base_name = full_name.split(":")[0]
                            model_names.append(base_name)
                    
                    logger.info(f"Available Ollama models: {model_names}")
                    logger.info(f"Looking for model: {self.model}")
                    
                    if self.model in model_names:
                        logger.info(f"Model {self.model} found!")
                        return True
                    else:
                        logger.warning(f"Model {self.model} not found. Available models: {model_names}")
                        return False
            return False
        except Exception as e:
            logger.error(f"Error connecting to Ollama: {str(e)}")
            return False

    def query_ollama(self, prompt: str, temperature: float = 0.2, timeout: int = 10) -> str:
        """Send a query to the Ollama API and get the response"""
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "stream": False
                },
                timeout=timeout  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                logger.error(f"Error from Ollama API: {response.status_code}, {response.text}")
                return ""
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while querying Ollama after {timeout} seconds")
            return ""
        except Exception as e:
            logger.error(f"Exception while querying Ollama: {str(e)}")
            return ""

    def assess_cyber_relevance(self, content: str) -> Tuple[bool, str]:
        """Use Ollama to assess if content is relevant to cybersecurity"""
        # Limit content length to avoid timeouts
        content_limited = content[:800]  # Even shorter limit
        
        prompt = f"""Is this text related to cybersecurity (YES/NO)?

Text: {content_limited}

Answer YES or NO only.
"""
        response = self.query_ollama(prompt, timeout=120)  # Shorter timeout
        
        # Parse the response
        is_relevant = False
        reason = "Not determined"
        
        if response:
            if "YES" in response.upper():
                is_relevant = True
                reason = "LLM determined content is relevant to cybersecurity"
            elif "NO" in response.upper():
                is_relevant = False
                reason = "LLM determined content is not relevant to cybersecurity"
        
        return is_relevant, reason

    def enhance_entry(self, entry: Dict) -> Dict:
        """Use Ollama to enhance an entry with more comprehensive cybersecurity information"""
        # Extract the key fields that might contain useful information
        content = ""
        
        # Special handling for Ubuntu security notices and similar formats
        if 'summary' in entry and isinstance(entry['summary'], str):
            content = f"Summary: {entry['summary']}\n"
            if 'title' in entry:
                content = f"Title: {entry['title']}\n" + content
                
        # If we don't have content yet, try other fields 
        if len(content) < 50:
            # Convert different formats to a text representation
            for key, value in entry.items():
                if isinstance(value, str) and len(value) > 10:  # Only include substantial text fields
                    # Skip fields that are likely not useful for content analysis
                    if key.lower() not in ['link', 'href', 'url', 'id', 'guid']:
                        content += f"{key}: {value[:200]}\n"  # Limit each field
        
        logger.info(f"Content for enhancement: {len(content)} chars")
        
        # Skip enhancement for large entries to avoid overloading the LLM
        if len(content) > 1000:  # Further reduced from 2000 to 1000
            logger.info(f"Skipping LLM enhancement for large entry ({len(content)} chars)")
            return entry
            
        # Skip if content is too small
        if len(content) < 50:
            logger.info("Skipping LLM enhancement for very small entry")
            return entry
        
        # Limit content to 800 chars maximum
        content_limited = content[:800]
        
        prompt = f"""Analyze this cybersecurity information and create a JSON with these fields:
description: Brief technical description
risk_level: Critical, High, Medium, or Low
affected_systems: List as array
mitigations: Main recommendation

Content: {content_limited}
"""
        
        logger.info("Sending prompt to Ollama")
        # Use a shorter timeout (3 seconds) to prevent long waits
        response = self.query_ollama(prompt, timeout=120)
        logger.info(f"Received response from Ollama: {len(response) if response else 0} chars")
        
        # Try to parse the JSON response
        try:
            # First check if we have JSON delimiters and extract just the JSON
            if "```json" in response and "```" in response.split("```json", 1)[1]:
                json_content = response.split("```json", 1)[1].split("```", 1)[0].strip()
                enhanced_data = json.loads(json_content)
            elif "```" in response and "```" in response.split("```", 1)[1]:
                json_content = response.split("```", 1)[1].split("```", 1)[0].strip()
                enhanced_data = json.loads(json_content)
            else:
                # Try to parse the whole response
                enhanced_data = json.loads(response)
                
            # Add enhanced data to the entry
            entry["enhanced"] = enhanced_data
            return entry
            
        except json.JSONDecodeError:
            # If we can't parse as JSON, just add the raw response
            logger.warning("Could not parse LLM response as JSON")
            entry["enhanced_text"] = response
            return entry

    def load_data(self, file_path: Path) -> Union[Dict, List, None]:
        """Load data from various file formats."""
        try:
            suffix = file_path.suffix.lower()
            if suffix == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            elif suffix == '.yaml' or suffix == '.yml':
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

    def is_relevant_content(self, text: str) -> bool:
        """
        Check if the content is relevant to cybersecurity using rule-based method.
        Returns True if content is relevant, False otherwise.
        """
        if not isinstance(text, str):
            return False
            
        # Check minimum length
        if len(text) < self.min_content_length:
            return False
            
        # Check for exclusion patterns
        for pattern in self.exclusion_patterns.values():
            if re.search(pattern, text, re.IGNORECASE):
                return False
        
        # Count keyword matches
        text_lower = text.lower()
        high_relevance_matches = sum(1 for kw in self.cybersecurity_keywords['high_relevance'] 
                                   if kw.lower() in text_lower)
        medium_relevance_matches = sum(1 for kw in self.cybersecurity_keywords['medium_relevance'] 
                                     if kw.lower() in text_lower)
        
        # Scoring system: high relevance keywords count as 2, medium as 1
        relevance_score = (high_relevance_matches * 2) + medium_relevance_matches
        
        return relevance_score >= self.min_keyword_matches

    def filter_entry(self, entry: Dict) -> Tuple[bool, str]:
        """
        Filter a single entry based on relevance criteria.
        Returns (is_relevant, reason).
        """
        # Combine all text fields for analysis
        text_content = []
        for key, value in entry.items():
            if isinstance(value, str):
                text_content.append(value)
            elif isinstance(value, (dict, list)):
                text_content.append(str(value))
        
        combined_text = ' '.join(text_content)
        
        if not combined_text.strip():
            return False, "Empty content"
        
        # If Ollama is available, use it for better relevance assessment
        if self.ollama_available:
            is_relevant, reason = self.assess_cyber_relevance(combined_text[:4000])  # Limit length
            return is_relevant, reason
        else:
            # Fall back to rule-based method
            if not self.is_relevant_content(combined_text):
                return False, "Not relevant to cybersecurity (rule-based)"
            
            return True, "Relevant (rule-based)"

    def filter_dataset(self, input_file: Path) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter the dataset and return (relevant_entries, filtered_out_entries).
        """
        data = self.load_data(input_file)
        if not data:
            return [], []
        
        # Convert to list if dictionary
        if isinstance(data, dict):
            # Special case for files with 'entries' key (like Ubuntu security notices)
            if 'entries' in data and isinstance(data['entries'], list):
                logger.info(f"Processing {len(data['entries'])} entries from 'entries' key")
                data = data['entries']
            else:
                data = [data]
        
        logger.info(f"Processing {len(data)} total entries")
        
        relevant_entries = []
        filtered_out_entries = []
        
        # Process just a sample for testing if there are many entries
        process_count = min(len(data), 5)  # Process at most 5 entries for testing
        logger.info(f"Processing all entries")
        
        for i, entry in enumerate(data[:process_count]):
            logger.info(f"Processing entry {i+1}/{process_count}")
            is_relevant, reason = self.filter_entry(entry)
            if is_relevant:
                # Enhance entry if Ollama is available
                if self.ollama_available:
                    entry = self.enhance_entry(entry)
                relevant_entries.append(entry)
            else:
                entry['filtered_reason'] = reason
                filtered_out_entries.append(entry)
            
            # Add a small delay to avoid overwhelming Ollama
            if self.ollama_available:
                time.sleep(0.1)
        
        logger.info(f"Finished processing {process_count} entries: {len(relevant_entries)} relevant, {len(filtered_out_entries)} filtered out")
        return relevant_entries, filtered_out_entries

    def save_filtered_data(self, data: List[Dict], original_file: Path, suffix: str = '') -> bool:
        """Save filtered data with original format."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"{original_file.stem}{suffix}_{timestamp}{original_file.suffix}"
            
            if original_file.suffix.lower() == '.json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            elif original_file.suffix.lower() in {'.yaml', '.yml'}:
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, allow_unicode=True)
            elif original_file.suffix.lower() == '.csv':
                pd.DataFrame(data).to_csv(output_file, index=False)
            
            logger.info(f"Saved filtered data to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving filtered data: {str(e)}")
            return False

    def process_directory(self, limit=5):
        """Process files in the input directory, limited to a specified number for testing."""
        total_stats = {
            'processed_files': 0,
            'total_entries': 0,
            'retained_entries': 0,
            'filtered_entries': 0
        }
        
        # Process only limited number of files (for testing)
        # To process ALL files, remove the limit by changing the line below to:
        # for file_path in self.input_dir.glob('*.*'):
        files_to_process = list(self.input_dir.glob('*.*'))
        
        # If limit is 1, prioritize processing Ubuntu security data which is smaller
        if limit == 1:
            ubuntu_files = [f for f in files_to_process if 'ubuntu_security' in f.name]
            if ubuntu_files:
                files_to_process = ubuntu_files[:1]
                logger.info("Prioritizing Ubuntu security data file for testing")
        
        # Limit the number of files if specified
        if limit:
            files_to_process = files_to_process[:limit]
            
        for file_path in files_to_process:
            if file_path.suffix.lower() not in {'.json', '.yaml', '.yml', '.csv'}:
                continue
                
            logger.info(f"Processing {file_path} (file {total_stats['processed_files'] + 1} of {len(files_to_process)})")
            relevant_entries, filtered_entries = self.filter_dataset(file_path)
            
            if relevant_entries or filtered_entries:
                total_stats['processed_files'] += 1
                total_stats['total_entries'] += len(relevant_entries) + len(filtered_entries)
                total_stats['retained_entries'] += len(relevant_entries)
                total_stats['filtered_entries'] += len(filtered_entries)
                
                # Save relevant entries
                if relevant_entries:
                    self.save_filtered_data(relevant_entries, file_path, '_filtered')
                
                # Optionally save filtered-out entries for analysis
                if filtered_entries:
                    self.save_filtered_data(filtered_entries, file_path, '_removed')
        
        # Log statistics
        logger.info("Filtering Statistics:")
        logger.info(f"Processed Files: {total_stats['processed_files']}")
        logger.info(f"Total Entries: {total_stats['total_entries']}")
        logger.info(f"Retained Entries: {total_stats['retained_entries']}")
        logger.info(f"Filtered Entries: {total_stats['filtered_entries']}")
        
        if total_stats['total_entries'] > 0:
            retention_rate = (total_stats['retained_entries'] / total_stats['total_entries'] * 100)
            logger.info(f"Retention Rate: {retention_rate:.2f}%")

def main():
    """Main function to process command-line arguments and run the filter."""
    parser = argparse.ArgumentParser(description="Filter cybersecurity data using Ollama LLM")
    parser.add_argument("--input-dir", default="raw_data", help="Directory containing raw data")
    parser.add_argument("--output-dir", default="filtered_data", help="Directory to save filtered data")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="URL for Ollama API")
    parser.add_argument("--limit", type=int, default=5, help="Limit the number of files to process (default: 5, set to 0 for no limit)")
    parser.add_argument("--disable-ollama", action="store_true", help="Disable using Ollama and use only rule-based filtering")
    
    args = parser.parse_args()
    
    filter = CyberDataFilter(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        ollama_url=args.ollama_url
    )
    
    # If Ollama is explicitly disabled, override the availability check
    if args.disable_ollama:
        filter.ollama_available = False
        logger.info("Ollama usage explicitly disabled by command-line flag")
    
    # Pass the limit parameter to process_directory
    # To process ALL files, set --limit 0 or remove the limit argument
    limit = args.limit if args.limit > 0 else None
    filter.process_directory(limit)

if __name__ == "__main__":
    main() 