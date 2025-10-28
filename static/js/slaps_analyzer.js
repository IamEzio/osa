$(document).ready(function () {
  $("#uploadForm").on("submit", function (e) {
    e.preventDefault();
    const formData = new FormData(this);
    $("#resultsSection").addClass("d-none");
    $("#results").html(
      '<div class="text-center text-muted">Analyzing report... please wait.</div>'
    );
    $.ajax({
      url: "/analyze", // Flask backend endpoint
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        $("#resultsSection").removeClass("d-none");
        $("#results").html(renderResults(response));
      },
      error: function () {
        $("#results").html(
          '<div class="text-danger text-center">Error analyzing file. Please try again.</div>'
        );
      },
    });
  });

  // Renders the results with checkboxes and one Remediate Selected button per artifact
  function renderResults(data) {
    let html = "";
    Object.keys(data).forEach((artifact, i) => {
      html += `
        <div class="accordion mb-3" id="artifact-${i}">
          <div class="accordion-item">
            <h2 class="accordion-header" id="heading-${i}">
              <button class="accordion-button collapsed fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${i}">
                ${artifact}
              </button>
            </h2>
            <div id="collapse-${i}" class="accordion-collapse collapse">
              <div class="accordion-body">
                <form class="findings-form" data-artifact="${artifact}" id="findings-form-${i}">
                  ${renderPackages(data[artifact], i)}
                  <div class="text-end mt-3">
                    <button type="button" class="btn btn-danger btn-sm remediate-selected-btn" data-artifact="${artifact}" data-artifact-index="${i}">
                      Remediate Selected
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>`;
    });
    return html;
  }

  function renderPackages(findings, artifactIndex) {
    let html = "";
    findings.forEach((finding, j) => {
      let meta = finding.metadata || {};
      html += `
        <div class="accordion mb-2" id="pkg-${artifactIndex}-${j}">
            <div class="accordion-item">
                <h2 class="accordion-header d-flex align-items-center" id="pkg-head-${artifactIndex}-${j}">
                    <input type="checkbox" class="form-check-input ms-2 finding-checkbox" 
                        style="margin-right:12px" data-finding-index="${j}" 
                        name="finding-checkbox-${artifactIndex}-${j}">
                    <button class="accordion-button collapsed fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#pkg-collapse-${artifactIndex}-${j}">
                        ${meta.Package_Name || "Unknown Package"} - ${
        meta.Package_Version || finding.Package_Version || "N/A"
      }
                    </button>
                </h2>
                <div id="pkg-collapse-${artifactIndex}-${j}" class="accordion-collapse collapse">
                    <div class="accordion-body">
                        <table class="table table-sm table-bordered">
                            <thead class="table-light">
                                <tr>
                                    <th>Severity</th>
                                    <th>Advisory</th>
                                    <th>Current Version</th>
                                    <th>Fix Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><span class="badge bg-${getSeverityColor(
                                      meta.Severity || finding.severity
                                    )}">${
        meta.Severity || finding.severity
      }</span></td>
                                    <td><a href="${
                                      meta.Advisory_Link ||
                                      finding.Advisory_Link ||
                                      "#"
                                    }" target="_blank">${
        meta.Advisory_Name || finding.Advisory_Name || "N/A"
      }</a></td>
                                    <td>${
                                      meta.Package_Version ||
                                      finding.Package_Version ||
                                      "N/A"
                                    }</td>
                                    <td>${
                                      meta.CVE_Fix_Version ||
                                      finding.CVE_Fix_Version ||
                                      "N/A"
                                    }</td>
                                </tr>
                            </tbody>
                        </table>
                        <div>
                            <strong>Summary:</strong> ${finding.summary || ""}
                        </div>
                        <div>
                            <strong>Details:</strong> <pre>${
                              finding.details ? finding.details : ""
                            }</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
    });
    return html;
  }

  function getSeverityColor(sev) {
    if (!sev) return "secondary";
    sev = sev.toLowerCase();
    if (sev.includes("critical")) return "danger";
    if (sev.includes("high")) return "warning";
    if (sev.includes("medium")) return "info";
    return "secondary";
  }

  // Event delegation for dynamically generated Remediate Selected buttons
  $(document).on("click", ".remediate-selected-btn", function () {
    const artifact = $(this).data("artifact");
    const artifactIndex = $(this).data("artifact-index");
    // Find all checked checkboxes within this form
    const checked = $(
      `#findings-form-${artifactIndex} .finding-checkbox:checked`
    );
    if (checked.length === 0) {
      alert("Please select at least one finding to remediate.");
      return;
    }
    const indexes = [];
    checked.each(function () {
      indexes.push(parseInt($(this).data("finding-index")));
    });

    // POST to remediate with artifact and indexes
    $.ajax({
      url: "/api/remediate", // Update endpoint
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify({
        artifact: artifact,
        finding_indexes: indexes,
      }),
      success: function (response) {
        window.location.href =
          "/remediate/" + encodeURIComponent(artifact);
      },
      error: function () {
        alert("Error while submitting remediation request.");
      },
    });
  });
});
