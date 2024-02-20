document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/data')
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('scan-results');
        data.scans.forEach(scan => {
            const card = `<div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Scan at ${scan.host}</h5>
                                <p class="card-text">${JSON.stringify(scan[0])}</p>
                            </div>
                          </div>`;
            container.innerHTML += card;
        });
    })
    .catch(error => console.error('Error:', error));
});
