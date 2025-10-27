# MISP DDoS Events Exporter

Automated export of DDoS-related threat intelligence events from a self-hosted MISP instance. This repository automatically updates with the latest DDoS events that have TLP:GREEN or TLP:CLEAR classifications, making them suitable for community sharing.

## 📊 Data Consumer

The exported JSON file (`ddos_events.json`) is consumed by a separate GitHub Pages repository for static display of threat intelligence data. The JSON structure is designed to be stable and predictable for reliable parsing.

## 🔗 Access the Data

**Raw JSON URL:**
```
https://raw.githubusercontent.com/PabloPenguin/misp-ddos-events/main/ddos_events.json
```

Use this URL to fetch the latest DDoS events data in your applications or GitHub Pages site.

## 🏗️ Architecture

- **MISP Instance**: Self-hosted MISP server with DDoS threat intelligence
- **GitHub Runner**: Self-hosted runner with Tailscale for secure MISP access
- **Automation**: GitHub Actions workflow runs daily to export and commit updates
- **Output**: JSON file with complete event details, tags, attributes, and intelligence

## 🚀 Setup Instructions

### Prerequisites

1. **Self-hosted MISP instance** with API access
2. **Self-hosted GitHub runner** configured with:
   - Tailscale connectivity to MISP server
   - Python 3.11+ installed
   - Git configured
3. **GitHub repository** (this repo) with appropriate permissions

### Configuration Steps

#### 1. Configure GitHub Secrets

Add the following secrets to your repository (Settings → Secrets and variables → Actions):

- `MISP_URL`: Your MISP instance URL (e.g., `https://misp.yourdomain.com`)
- `MISP_API_KEY`: Your MISP API authentication key

**To get your MISP API key:**
1. Log into your MISP instance
2. Navigate to: My Profile → Auth Keys
3. Create a new API key or copy an existing one

#### 2. Set Up Self-Hosted Runner

**Register the runner:**
```bash
# Follow GitHub's instructions at:
# Settings → Actions → Runners → New self-hosted runner
```

**Install Python dependencies on the runner:**
```bash
pip install -r requirements.txt
```

**Ensure Tailscale is running:**
```bash
# Verify Tailscale status
tailscale status

# Verify connectivity to MISP
curl https://your-misp-instance.com
```

#### 3. Configure the Workflow

The workflow is located at `.github/workflows/export-events.yml` and runs:
- **Daily at 2 AM UTC** (via cron schedule)
- **Manually** (via workflow_dispatch)

To change the schedule, edit the cron expression:
```yaml
schedule:
  - cron: '0 2 * * *'  # Adjust this line
```

#### 4. Initial Test Run

Trigger a manual run to test the setup:

1. Go to **Actions** tab in your repository
2. Select **Export MISP DDoS Events** workflow
3. Click **Run workflow**
4. Monitor the execution logs

### Verification

After a successful run, you should see:
- ✅ A new `ddos_events.json` file in the repository
- ✅ A commit with the message format: `Update DDoS events data - X events [timestamp]`
- ✅ Workflow summary showing export statistics

## 📄 JSON Structure

The exported JSON follows this structure:

```json
{
  "export_metadata": {
    "export_date": "2025-10-27T02:00:00Z",
    "schema_version": "1.0",
    "filter_criteria": {
      "event_type": "DDoS",
      "tlp_levels": ["tlp:green", "tlp:clear", "tlp:white"],
      "published_only": true
    },
    "total_events": 42,
    "repository": "https://github.com/PabloPenguin/misp-ddos-events"
  },
  "events": [
    {
      "event_id": "123",
      "event_uuid": "...",
      "info": "DDoS Attack Campaign...",
      "date": "2025-10-26",
      "timestamp": "1729900800",
      "published": true,
      "tlp_level": "TLP:GREEN",
      "threat_level": "3",
      "analysis": "1",
      "tags": ["ddos", "misp-galaxy:threat-actor=\"...\""],
      "attributes": [
        {
          "id": "456",
          "type": "ip-dst",
          "category": "Network activity",
          "value": "192.0.2.1",
          "comment": "C2 server",
          "to_ids": true,
          "timestamp": "1729900800"
        }
      ],
      "galaxies": [...],
      "related_events": [...],
      "attribute_count": 15,
      "org_name": "Your Organization",
      "org_uuid": "..."
    }
  ]
}
```

## 🔒 Security & TLP Compliance

This exporter strictly filters events based on Traffic Light Protocol (TLP) classifications:

- ✅ **TLP:CLEAR** (formerly TLP:WHITE) - Information can be shared freely
- ✅ **TLP:GREEN** - Information can be shared within the community
- ❌ **TLP:AMBER** - Restricted sharing (excluded)
- ❌ **TLP:RED** - No sharing outside organization (excluded)

**Important:** Only events explicitly tagged with TLP:GREEN or TLP:CLEAR are exported. Events without TLP tags are included by default (assumed shareable).

## 🔍 Event Filtering

Events are identified as DDoS-related based on:

**Keywords in event info/title:**
- ddos
- denial-of-service
- dos-attack
- amplification
- reflection-attack
- syn-flood
- udp-flood
- http-flood
- volumetric-attack

**Tags:**
- Any tag containing the above keywords

The filter criteria can be adjusted in `export_misp_events.py` in the `DDOS_KEYWORDS` list.

## 🛠️ Manual Execution

You can also run the export script manually:

```bash
# Set environment variables
export MISP_URL="https://your-misp-instance.com"
export MISP_API_KEY="your-api-key"
export OUTPUT_FILE="ddos_events.json"

# Run the script
python export_misp_events.py
```

## 📊 GitHub Pages Integration

To consume this data in a GitHub Pages site:

```javascript
// Fetch the JSON data
fetch('https://raw.githubusercontent.com/PabloPenguin/misp-ddos-events/main/ddos_events.json')
  .then(response => response.json())
  .then(data => {
    console.log(`Total DDoS events: ${data.export_metadata.total_events}`);
    
    // Display events
    data.events.forEach(event => {
      console.log(`Event: ${event.info}`);
      console.log(`TLP: ${event.tlp_level}`);
      console.log(`Attributes: ${event.attribute_count}`);
    });
  });
```

## 🐛 Troubleshooting

### Workflow fails with "Authentication failed"
- Verify `MISP_URL` and `MISP_API_KEY` secrets are correctly set
- Check MISP API key is valid and not expired
- Test API access from the runner: `curl -H "Authorization: YOUR_KEY" https://your-misp-url/events`

### No events exported (0 events)
- Verify your MISP instance has published DDoS events
- Check TLP tags on events (must be GREEN or CLEAR)
- Review filter keywords in `export_misp_events.py`

### Runner cannot connect to MISP
- Verify Tailscale is running: `tailscale status`
- Check network connectivity: `ping your-misp-instance`
- Verify firewall rules allow runner access

### JSON file not updating
- Check workflow logs for errors
- Verify runner has git push permissions
- Ensure `ddos_events.json` is not in `.gitignore`

## 📝 Customization

### Change Export Schedule

Edit `.github/workflows/export-events.yml`:

```yaml
schedule:
  - cron: '0 */6 * * *'  # Run every 6 hours
```

### Add More Event Types

Edit `export_misp_events.py` and update the `DDOS_KEYWORDS` list:

```python
DDOS_KEYWORDS = [
    'ddos',
    'malware',  # Add new keywords
    'phishing'
]
```

### Modify JSON Output

Customize the `format_event()` method in `export_misp_events.py` to include/exclude fields.

## 📜 License

This project is provided as-is for threat intelligence sharing purposes. Ensure compliance with your organization's data sharing policies and MISP instance terms of use.

## 🤝 Contributing

Contributions are welcome! Please ensure any changes maintain TLP compliance and backward compatibility with downstream consumers.

## 📞 Support

For issues with:
- **This exporter**: Open an issue in this repository
- **MISP API**: Consult [PyMISP documentation](https://github.com/MISP/PyMISP)
- **GitHub Actions**: Check [GitHub Actions documentation](https://docs.github.com/en/actions)

---

**Last Updated:** October 27, 2025  
**Maintained by:** PabloPenguin
