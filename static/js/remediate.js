$(function() {
    const artifact = ARTIFACT_NAME;
    // Load Vulnerabilities
    $.getJSON(`/api/vulnerabilities/${artifact}`, function(data) {
        if (!data || !Object.keys(data).length) {
            $('#vulnTable').html('<div class="alert alert-warning">No vulnerabilities found for this module.</div>');
            return;
        }
        let html = `
        <div class="table-container">
        <table class="table table-striped table-bordered align-middle">
            <thead class="table-light">
                <tr>
                    <th>Package</th>
                    <th>Severity</th>
                    <th>Advisory</th>
                    <th>Current Version</th>
                    <th>Fix Version</th>
                </tr>
            </thead>
            <tbody>`;
        Object.keys(data).forEach(pkg => {
            data[pkg].forEach(v => {
                html += `<tr>
                    <td>${pkg}</td>
                    <td><span class="badge bg-${getColor(v.Severity)}">${v.Severity}</span></td>
                    <td><a href="${v.Advisory_Link}" target="_blank">${v.Advisory_Name}</a></td>
                    <td>${v.Package_Version || 'N/A'}</td>
                    <td>${v.Fix_Version || 'N/A'}</td>
                </tr>`;
            });
        });
        html += '</tbody></table></div>';
        $('#vulnTable').html(html);
    });
    // Poll backend for status updates
    const POLL_MS = 5000;
    let pollTimer = null;
    function startPolling() {
        if (pollTimer) return;
        pollTimer = setInterval(fetchStatus, POLL_MS);
        fetchStatus();
    }
    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }
    function fetchStatus() {
        $.getJSON(`/api/build_status/${artifact}`, function(resp) {
            if (!resp) return;
            // While PR is being created
            if (!resp.pr_link) {
                $('#loaderSection').show();
                $('#loaderMsg').text(resp.message || 'Creating PR...');
                return;
            }
            // PR created — show table
            $('#loaderSection').hide();
            $('#statusSection').removeClass('d-none');
            // PR link
            $('#prCol').html(`<a href="${resp.pr_link}" class="text-decoration-none fw-semibold" target="_blank">${resp.pr_link}</a>`);
            // Status
            let statusBadge = `<span class="status-badge bg-secondary text-white">OPEN</span>`;
            if (resp.status === 'open') statusBadge = `<span class="status-badge bg-primary text-white">OPEN</span>`;
            if (resp.status === 'failed') statusBadge = `<span class="status-badge bg-danger text-white">FAILED</span>`;
            if (resp.status === 'success') statusBadge = `<span class="status-badge bg-success text-white">SUCCESS</span>`;
            $('#statusCol').html(statusBadge);
            // Build
            let buildCell = '-';
            if (resp.build === 'IN PROGRESS') {
                buildCell = `<div class="loader-inline text-primary"><div class="spinner-border spinner-border-sm"></div> In Progress</div>`;
            } else if (resp.build === 'successful') {
                buildCell = `<span class="status-badge bg-success text-white">SUCCESSFUL</span>`;
            } else if (resp.build === 'failed') {
                buildCell = `<span class="status-badge bg-danger text-white">FAILED</span>`;
            }
            $('#buildCol').html(buildCell);
            // Dev Release
            let releaseCell = '-';
            if (resp.dev_release_link === 'IN PROGRESS') {
                releaseCell = `<div class="loader-inline text-primary"><div class="spinner-border spinner-border-sm"></div> Creating...</div>`;
            } else if (resp.dev_release_link && typeof resp.dev_release_link === 'string' && resp.dev_release_link.startsWith('http')) {
                releaseCell = `<a href="${resp.dev_release_link}" target="_blank" class="status-badge bg-success text-white text-decoration-none">${resp.dev_release_name}</a>`;
            }
            $('#releaseCol').html(releaseCell);
            // stop polling if everything is done
            if (resp.build === 'successful' && (resp.dev_release_link === 'completed' || resp.dev_release_link?.startsWith('http'))) {
                stopPolling();
            }
        });
    }
    startPolling();
    function getColor(sev) {
        if (!sev) return 'secondary';
        const s = sev.toLowerCase();
        if (s.includes('critical')) return 'danger';
        if (s.includes('high')) return 'warning';
        if (s.includes('medium')) return 'info';
        return 'secondary';
    }
});