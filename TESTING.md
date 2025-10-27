# Workflow Testing Checklist

## Pre-Test Checklist
- [ ] Files pushed to GitHub (main branch)
- [ ] GitHub secrets configured (MISP_URL, MISP_API_KEY)
- [ ] Self-hosted runner is running on Linux server
- [ ] Runner shows "Idle" status in GitHub
- [ ] Tailscale is connected on runner server

## Testing Steps

### 1. Manual Workflow Test
```
https://github.com/PabloPenguin/misp-ddos-events/actions
→ "Export MISP DDoS Events"
→ "Run workflow" (dropdown)
→ Select "main" branch
→ Click "Run workflow"
```

### 2. Watch Execution
- Click on the workflow run that appears
- Monitor each step in real-time
- Check for any red ❌ errors

### 3. Expected Results
✅ All steps complete successfully
✅ New file `ddos_events.json` appears in repo
✅ Commit message: "Update DDoS events data - X events [timestamp]"
✅ Workflow summary shows export statistics

## Common Issues and Fixes

### Issue: "No runner matching the specified labels"
**Fix:** 
- Verify runner is running: `pgrep -f Runner.Listener` (on Linux server)
- Check runner status in GitHub UI
- Restart runner if needed: `cd ~/actions-runner && ./run.sh`

### Issue: "Authentication failed" / "Invalid MISP API key"
**Fix:**
- Verify MISP_URL and MISP_API_KEY secrets are set correctly
- Test API key manually:
  ```bash
  curl -H "Authorization: YOUR_API_KEY" "https://your-misp-url/servers/getPyMISPVersion.json"
  ```

### Issue: "Connection refused" / "Cannot connect to MISP"
**Fix:**
- Check Tailscale is running: `tailscale status`
- Test connectivity: `curl -I https://your-misp-instance`
- Verify MISP_URL format (should be https://... without trailing slash)

### Issue: "Module 'pymisp' not found"
**Fix:**
- Install dependencies on runner:
  ```bash
  cd ~/actions-runner
  pip3 install -r /path/to/requirements.txt
  ```
- Or the workflow should install them automatically

### Issue: "No events exported (0 events)"
**Possible causes:**
- No DDoS events in MISP with TLP:GREEN/CLEAR
- Check MISP has published events
- Verify event tags include DDoS-related keywords
- Check the filter criteria in export_misp_events.py

### Issue: "Permission denied" when pushing
**Fix:**
- Verify runner has git configured:
  ```bash
  git config --global user.name "github-actions[bot]"
  git config --global user.email "github-actions[bot]@users.noreply.github.com"
  ```
- Check GITHUB_TOKEN has write permissions

## Verification Commands

### On Linux Runner:
```bash
# Check runner status
pgrep -f Runner.Listener

# Check Tailscale
tailscale status

# Test MISP connectivity
curl -H "Authorization: YOUR_API_KEY" "https://your-misp-url/events"

# Check Python & PyMISP
python3 --version
python3 -c "import pymisp; print(pymisp.__version__)"
```

### In Browser:
```
# View workflow runs
https://github.com/PabloPenguin/misp-ddos-events/actions

# View exported JSON
https://github.com/PabloPenguin/misp-ddos-events/blob/main/ddos_events.json

# Raw JSON (for GitHub Pages)
https://raw.githubusercontent.com/PabloPenguin/misp-ddos-events/main/ddos_events.json

# Runner status
https://github.com/PabloPenguin/misp-ddos-events/settings/actions/runners
```

## Success Indicators
✅ Workflow run shows all green checkmarks
✅ Job summary displays event count and export date
✅ ddos_events.json file exists in repository
✅ JSON structure matches expected format
✅ Only TLP:GREEN and TLP:CLEAR events included
✅ Raw JSON URL is accessible

## Next Steps After Successful Test
- [ ] Verify JSON structure is correct
- [ ] Test JSON URL in your GitHub Pages site
- [ ] Wait for scheduled run (2 AM UTC) or adjust schedule
- [ ] Monitor for any errors over next few runs
- [ ] Set up notifications for workflow failures (optional)
