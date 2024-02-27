document.addEventListener('DOMContentLoaded', function() {
    const clientId = '{{ client_id }}'; // L'ID du client est injecté par Flask lors du rendu de la page
    fetch(`/api/clients/${clientId}/details`)
    .then(response => response.json())
    .then(data => {
        const clientDetailsElement = document.getElementById('clientDetails');
        data.forEach(scan => {
            const scanElement = document.createElement('div');
            scanElement.classList.add('scan-section');

            for (const [key, value] of Object.entries(scan)) {
                if (key === 'open_ports') {
                    const portsTitle = document.createElement('h4');
                    portsTitle.textContent = 'Ports Ouverts';
                    scanElement.appendChild(portsTitle);

                    value.forEach(portInfo => {
                        const portElement = document.createElement('div');
                        portElement.classList.add('port-info');
                        for (const [portKey, portValue] of Object.entries(portInfo)) {
                            const portDetailElement = document.createElement('p');
                            portDetailElement.textContent = `${portKey}: ${portValue}`;
                            portElement.appendChild(portDetailElement);
                        }
                        scanElement.appendChild(portElement);
                    });
                } else {
                    const keyValueElement = document.createElement('p');
                    keyValueElement.textContent = `${key}: ${value}`;
                    scanElement.appendChild(keyValueElement);
                }
            }

            clientDetailsElement.appendChild(scanElement);
        });
    })
    .catch(error => console.error('Error:', error));
});