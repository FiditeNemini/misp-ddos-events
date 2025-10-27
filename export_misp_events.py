#!/usr/bin/env python3
"""
MISP DDoS Events Exporter
Exports DDoS-related events with TLP:GREEN or less from MISP to JSON format.
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import List, Dict, Any

try:
    from pymisp import PyMISP
except ImportError:
    print("Error: PyMISP library not found. Install it with: pip install pymisp")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MISPDDoSExporter:
    """Exports DDoS events from MISP with TLP filtering."""
    
    # TLP levels that are allowed (GREEN and CLEAR/WHITE)
    ALLOWED_TLP_LEVELS = ['tlp:green', 'tlp:clear', 'tlp:white']
    
    # DDoS-related tags and keywords to filter events
    DDOS_KEYWORDS = [
        'ddos',
        'denial-of-service',
        'dos-attack',
        'amplification',
        'reflection-attack',
        'syn-flood',
        'udp-flood',
        'http-flood',
        'volumetric-attack'
    ]
    
    def __init__(self, misp_url: str, misp_key: str):
        """
        Initialize MISP connection.
        
        Args:
            misp_url: URL of the MISP instance
            misp_key: API key for authentication
        """
        self.misp = PyMISP(misp_url, misp_key, ssl=True)
        logger.info(f"Connected to MISP instance: {misp_url}")
    
    def is_tlp_allowed(self, event: Dict[str, Any]) -> bool:
        """
        Check if event has allowed TLP level.
        
        Args:
            event: MISP event dictionary
            
        Returns:
            True if TLP level is GREEN or CLEAR, False otherwise
        """
        tags = event.get('Tag', [])
        
        # Check if event has any TLP tags
        tlp_tags = [tag['name'].lower() for tag in tags if 'tlp:' in tag['name'].lower()]
        
        # If no TLP tag, assume it's shareable (default to allowed)
        if not tlp_tags:
            logger.debug(f"Event {event.get('id')} has no TLP tag, allowing by default")
            return True
        
        # Check if any TLP tag is in allowed list
        for tlp_tag in tlp_tags:
            if any(allowed in tlp_tag for allowed in self.ALLOWED_TLP_LEVELS):
                return True
        
        logger.debug(f"Event {event.get('id')} has restricted TLP: {tlp_tags}")
        return False
    
    def is_ddos_event(self, event: Dict[str, Any]) -> bool:
        """
        Check if event is DDoS-related.
        
        Args:
            event: MISP event dictionary
            
        Returns:
            True if event is DDoS-related, False otherwise
        """
        # Check event info/title
        event_info = event.get('info', '').lower()
        
        # Check tags
        tags = event.get('Tag', [])
        tag_names = [tag['name'].lower() for tag in tags]
        
        # Check if any DDoS keyword matches
        for keyword in self.DDOS_KEYWORDS:
            if keyword in event_info or any(keyword in tag for tag in tag_names):
                return True
        
        return False
    
    def export_events(self) -> List[Dict[str, Any]]:
        """
        Export DDoS events with allowed TLP levels from MISP.
        
        Returns:
            List of filtered and formatted events
        """
        logger.info("Fetching events from MISP...")
        
        # Search for events (fetch all, then filter)
        # Note: Adjust the limit and parameters based on your MISP instance size
        events = self.misp.search(
            pythonify=False,
            limit=1000,  # Adjust as needed
            published=True  # Only published events
        )
        
        if not events or 'response' not in events:
            logger.warning("No events found in MISP")
            return []
        
        all_events = events['response']
        logger.info(f"Retrieved {len(all_events)} total events from MISP")
        
        # Filter events
        filtered_events = []
        for event in all_events:
            event_data = event.get('Event', event)
            
            # Check if DDoS-related and TLP-allowed
            if self.is_ddos_event(event_data) and self.is_tlp_allowed(event_data):
                filtered_events.append(self.format_event(event_data))
        
        logger.info(f"Filtered to {len(filtered_events)} DDoS events with TLP:GREEN or less")
        return filtered_events
    
    def format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format event data for export.
        
        Args:
            event: Raw MISP event
            
        Returns:
            Formatted event dictionary
        """
        # Extract TLP level
        tlp_level = "TLP:CLEAR"  # Default
        for tag in event.get('Tag', []):
            if 'tlp:' in tag['name'].lower():
                tlp_level = tag['name'].upper()
                break
        
        # Extract attributes
        attributes = []
        for attr in event.get('Attribute', []):
            attributes.append({
                'id': attr.get('id'),
                'type': attr.get('type'),
                'category': attr.get('category'),
                'value': attr.get('value'),
                'comment': attr.get('comment', ''),
                'to_ids': attr.get('to_ids', False),
                'timestamp': attr.get('timestamp')
            })
        
        # Extract tags
        tags = [tag['name'] for tag in event.get('Tag', [])]
        
        # Extract galaxies
        galaxies = []
        for galaxy in event.get('Galaxy', []):
            galaxies.append({
                'name': galaxy.get('name'),
                'type': galaxy.get('type'),
                'description': galaxy.get('description', '')
            })
        
        # Extract related events
        related_events = []
        for related in event.get('RelatedEvent', []):
            related_event = related.get('Event', {})
            related_events.append({
                'id': related_event.get('id'),
                'info': related_event.get('info'),
                'date': related_event.get('date')
            })
        
        return {
            'event_id': event.get('id'),
            'event_uuid': event.get('uuid'),
            'info': event.get('info'),
            'date': event.get('date'),
            'timestamp': event.get('timestamp'),
            'published': event.get('published', False),
            'tlp_level': tlp_level,
            'threat_level': event.get('threat_level_id'),
            'analysis': event.get('analysis'),
            'tags': tags,
            'attributes': attributes,
            'galaxies': galaxies,
            'related_events': related_events,
            'attribute_count': len(attributes),
            'org_name': event.get('Org', {}).get('name', ''),
            'org_uuid': event.get('Org', {}).get('uuid', '')
        }
    
    def create_export_json(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create the final export JSON structure.
        
        Args:
            events: List of formatted events
            
        Returns:
            Complete export dictionary with metadata
        """
        return {
            'export_metadata': {
                'export_date': datetime.utcnow().isoformat() + 'Z',
                'schema_version': '1.0',
                'filter_criteria': {
                    'event_type': 'DDoS',
                    'tlp_levels': self.ALLOWED_TLP_LEVELS,
                    'published_only': True
                },
                'total_events': len(events),
                'repository': 'https://github.com/PabloPenguin/misp-ddos-events'
            },
            'events': events
        }


def main():
    """Main execution function."""
    # Get configuration from environment variables
    misp_url = os.getenv('MISP_URL')
    misp_key = os.getenv('MISP_API_KEY')
    output_file = os.getenv('OUTPUT_FILE', 'ddos_events.json')
    
    if not misp_url or not misp_key:
        logger.error("Missing required environment variables: MISP_URL and MISP_API_KEY")
        sys.exit(1)
    
    try:
        # Initialize exporter
        exporter = MISPDDoSExporter(misp_url, misp_key)
        
        # Export events
        events = exporter.export_events()
        
        # Create JSON structure
        export_data = exporter.create_export_json(events)
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Successfully exported {len(events)} events to {output_file}")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Export Summary")
        print(f"{'='*60}")
        print(f"Total DDoS Events Exported: {len(events)}")
        print(f"Output File: {output_file}")
        print(f"Export Date: {export_data['export_metadata']['export_date']}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logger.error(f"Error during export: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
