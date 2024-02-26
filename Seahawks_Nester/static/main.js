document.addEventListener('DOMContentLoaded', function() {
    function fetchData() {
        fetch('/api/data')
        .then(response => response.json())
        .then(clients => {
            const clientListContainer = document.getElementById('client-list');
            const scanResultsContainer = document.getElementById('scan-results');
            clientListContainer.innerHTML = ''; // Efface la liste des clients précédente
            scanResultsContainer.innerHTML = ''; // Efface les détails du scan précédent

            // Ajoute les clients à la liste
            Object.keys(clients).forEach(clientId => {
                const li = document.createElement('li');
                li.className = 'list-group-item list-group-item-action';
                li.textContent = `Client ${clientId}`;
                li.onclick = () => displayClientData(clientId, clients[clientId]);
                clientListContainer.appendChild(li);
            });
        });
    }

    function displayClientData(clientId, clientData) {
        const container = document.getElementById('scan-results');
        container.innerHTML = ''; // Efface les détails précédents

        // Affiche les données pour le client sélectionné
        const title = document.createElement('h3');
        title.textContent = `Data for Client ${clientId}`;
        container.appendChild(title);

        const dataList = document.createElement('ul');
        dataList.className = 'list-group';
        clientData.forEach(data => {
            const item = document.createElement('li');
            item.className = 'list-group-item';
            item.textContent = JSON.stringify(data);
            dataList.appendChild(item);
        });
        container.appendChild(dataList);
    }

    fetchData(); // Appelle fetchData au chargement de la page
});
