document.addEventListener('DOMContentLoaded', function() {
    function fetchClients() {
        fetch('/api/clients')
            .then(response => response.json())
            .then(clientIds => {
                const clientListContainer = document.getElementById('client-list');
                clientListContainer.innerHTML = ''; // Efface la liste des clients précédente

                // Ajoute les clients à la liste
                clientIds.forEach(clientId => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item list-group-item-action';
                    li.textContent = `Client ${clientId}`;
                    li.onclick = () => fetchClientData(clientId);
                    clientListContainer.appendChild(li);
                });
            })
            .catch(error => console.error('Error fetching client list:', error));
    }

    function fetchClientData(clientId) {
        fetch(`/api/clients/${clientId}`)
            .then(response => response.json())
            .then(clientData => {
                displayClientData(clientId, clientData);
            })
            .catch(error => console.error(`Error fetching data for client ${clientId}:`, error));
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
            // Formate les données si nécessaire ou les affiche directement
            item.textContent = JSON.stringify(data, null, 2); // Met en forme les données JSON
            dataList.appendChild(item);
        });
        container.appendChild(dataList);
    }

    fetchClients(); // Appelle fetchClients au chargement de la page pour lister tous les clients
});
