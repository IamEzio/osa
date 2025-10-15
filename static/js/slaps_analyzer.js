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
                            ${renderPackages(data[artifact], i)}
                        </div>
                    </div>
                </div>
            </div>`;
    });
    return html;
  }

  function renderPackages(packages, artifactIndex) {
    let html = "";
    Object.keys(packages).forEach((pkg, j) => {
      html += `
        <div class="accordion mb-2" id="pkg-${artifactIndex}-${j}">
            <div class="accordion-item">
                <h2 class="accordion-header" id="pkg-head-${artifactIndex}-${j}">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#pkg-collapse-${artifactIndex}-${j}">
                        ${pkg}
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
                                ${packages[pkg]
                                  .map(
                                    (v) => `
                                    <tr>
                                        <td><span class="badge bg-${getSeverityColor(
                                          v.Severity
                                        )}">${v.Severity}</span></td>
                                        <td><a href="${
                                          v.Advisory_Link
                                        }" target="_blank">${
                                      v.Advisory_Name
                                    }</a></td>
                                        <td>${v.Package_Version}</td>
                                        <td>${v.Fix_Version}</td>
                                    </tr>`
                                  )
                                  .join("")}
                            </tbody>
                        </table>
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
});
