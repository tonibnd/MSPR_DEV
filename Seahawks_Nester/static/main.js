document.addEventListener('DOMContentLoaded', function() {
    function fetchData() {
        fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('scan-results');
            // Efface le contenu précédent
            container.innerHTML = '';
            // Ajoute les nouvelles données
            data.scans.forEach(scan => {
                const card = `<div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">Scan at ${scan.host}</h5>
                                    <p class="card-text">${JSON.stringify(scan)}</p>
                                </div>
                              </div>`;
                container.innerHTML += card;
            });
        })
        .catch(error => console.error('Error:', error));
    }

    // Appel initial pour charger les données
    fetchData();

    // Optionnel: Rafraîchir les données à intervalles réguliers
    setInterval(fetchData, 60000); // Rafraîchit les données toutes les 10 secondes
});
