document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/clients')
    .then(response => response.json())
    .then(clients => {
        const clientListElement = document.getElementById('clientList');
        clients.forEach(clientId => {
            const listItem = document.createElement('li');
            const link = document.createElement('a');
            link.href = `/api/clients/${clientId}`;
            link.textContent = `Sonde ${clientId}`;
            listItem.appendChild(link);
            clientListElement.appendChild(listItem);
        });
    })
    .catch(error => console.error('Error:', error));
});