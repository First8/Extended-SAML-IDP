// export let selectedRealm;
function getAllPlugins(accessToken, selectedRealm) {
    if (selectedRealm) {
        fetch(`${ServerUrl}/admin/realms/${selectedRealm}/identity-provider/instances`, {
            method: 'GET',
            headers: {
                'Authorization': ` Bearer ${accessToken}`
            },
        })
            .then(async response => {
                if (response.ok) {
                    var plugins = await response.json();
                    console.log('All Plugins:', plugins);
                    updatePluginList(plugins, accessToken);
                } else {
                    console.error('Failed to fetch plugins:', response.status, response.statusText);
                }
            })
            .catch(error => {
                console.error('Error during the process:', error);
            });
    }
}
window.getAllPlugins = getAllPlugins;

function clearPluginList() {
    const pluginListContainer = document.getElementById('resultsContainer');
    while (pluginListContainer.firstChild) {
        pluginListContainer.removeChild(pluginListContainer.firstChild);
    }
}
window.clearPluginList = clearPluginList;

// Function to get the selected realm from sessionStorage



function getAllRealms(accessToken) {
    keycloak.updateToken(300).then((bool) => {
        fetch(`${ServerUrl}/admin/realms`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`
            },
        })
            .then(response => response.json())
            .then(async responseJSON => {
                try {
                    const realms = responseJSON;
                    console.log('realms:', realms);
                    const select_realms = document.getElementById('Realms');
                    while (select_realms.firstChild) {
                        select_realms.removeChild(select_realms.firstChild);
                    }
                    const emptyOption = document.createElement('option');
                    emptyOption.value = '';  // Set the value to an empty string
                    emptyOption.text = '';   // Set the text to an empty string
                    select_realms.add(emptyOption);

                    realms.forEach((realm, index) => {
                        const optionElement = document.createElement('option');
                        optionElement.value = realm.realm;
                        optionElement.text = realm.realm;
                        select_realms.add(optionElement);
                    });

                    select_realms.addEventListener('change', function () {
                        var selectedRealm = select_realms.value;
                        clearPluginList()
                        localStorage.setItem('selectedRealm', selectedRealm);
                        console.log(selectedRealm);
                        getAllPlugins(accessToken, selectedRealm);


                    });
                    updateSelectedRealm();
                } catch (error) {
                    console.error('Error during the process:', error);
                }
            })
            .catch(error => {
                console.error('Error during the process:', error);
            });
    });
}
window.getAllRealms = getAllRealms;
function updateSelectedRealm() {
    var selectedrealm = localStorage.getItem('selectedRealm');
    var select_realms = document.getElementById('Realms');

    if (select_realms && selectedrealm) {
        select_realms.value = selectedrealm;
        select_realms.dispatchEvent(new Event('change'));
    } else {
        console.log("selectedrealm undefined");
    }
}

updateSelectedRealm()
function updatePluginList(plugins, accessToken) {
    // Get the container where the results will be displayed
    var resultsContainer = document.getElementById('resultsContainer');

    if (resultsContainer) {
        // Create a table element
        var table = document.createElement('table');

        // Add the table header
        var headerRow = document.createElement('tr');
        var headerNameCell = document.createElement('th');
        headerNameCell.textContent = 'Name';
        var headerProviderCell = document.createElement('th');
        headerProviderCell.textContent = 'Provider details';
        var headerButtonCell = document.createElement('th');
        headerButtonCell.textContent = 'Actions';
        headerRow.appendChild(headerNameCell);
        headerRow.appendChild(headerProviderCell);
        headerRow.appendChild(headerButtonCell);
        table.appendChild(headerRow);

        // Add rows to the table
        plugins.forEach(plugin => {
            if (plugin.providerId == 'saml-extended') {
                var row = document.createElement('tr');

                // Create a link
                var link = document.createElement('a');
                link.href = `${editplugin}`;
                if (plugin.displayName) {
                    link.textContent = plugin.displayName;
                }
                else { link.textContent = plugin.alias; }



                // Add click event to the link
                link.addEventListener('click', async function (event) {
                    event.preventDefault();

                    try {
                        await getPluginDetails(plugin.alias);
                        await new Promise(resolve => setTimeout(resolve, 0));

                        window.location.href = `${editplugin}`;
                        localStorage.setItem('pluginalias', plugin.alias);
                    } catch (error) {
                        console.error('Error:', error);
                    }
                });


                // Add the link to the row
                var nameCell = document.createElement('td');
                nameCell.appendChild(link);
                row.appendChild(nameCell);

                // Add other information to the row
                var providerCell = document.createElement('td');
                providerCell.textContent = 'Saml-extended';
                row.appendChild(providerCell);

                // Add button without image
                var buttonCell = document.createElement('td');
                var button = document.createElement('button');
                button.classList.add('btn');
                button.textContent = 'Delete';
                button.addEventListener('click', function () {
                    if (confirm('Are you sure you want to delete this item?')) {
                        // If confirmation is accepted, execute the deletion
                        handleDeleteButtonClick(plugin.alias, accessToken);
                    }
                });
                buttonCell.appendChild(button);
                row.appendChild(buttonCell);

                // Add the row to the table
                table.appendChild(row);
            }
        });

        // Add the table to the results container
        resultsContainer.appendChild(table);
    } else {
        console.log("resultsContainer not exists");
    }
}
window.updatePluginList = updatePluginList;
function handleDeleteButtonClick(plugin_alias, accessToken) {
    keycloak.updateToken(300).then((bool) => {
        if (bool) {
            var selectedrealm = localStorage.getItem('selectedRealm');
            // Assuming you have an API endpoint for deleting plugins
            var deleteEndpoint = `${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${plugin_alias}`;
            var accessToken = keycloak.token;
            // Send a DELETE request using Fetch API
            fetch(deleteEndpoint, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json',
                    // You may need to include additional headers, such as authorization headers
                },
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to delete plugin');

                    }
                    var resultsContainer = document.getElementById('resultsContainer');
                    resultsContainer.innerHTML = '';

                    getAllPlugins(accessToken, selectedrealm);
                    alert(` ${plugin_alias} deleted successfully`)
                    // Optionally update the UI or perform additional actions on success
                })
                .catch(error => {
                    console.error('Error deleting plugin:', error.message);
                    // Handle the error as needed
                    alert('Failed to delete plugin. Please try again.');
                });

        }
    });
}
window.updatePluginList = updatePluginList;


function getPluginDetails(alias, accessToken) {
    return new Promise((resolve, reject) => {

        keycloak.updateToken(300).then((bool) => {
            if (bool) {
                console.log("Token is updated");
                var accessToken = keycloak.token;
                var selectedrealm = localStorage.getItem('selectedRealm');
                fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    },
                })
                    .then(async response => {
                        if (response.ok) {
                            var pluginData = await response.json();
                            localStorage.setItem('pluginData', JSON.stringify(pluginData));
                            console.log('Plugin Details:', pluginData);
                            resolve();
                        } else {
                            console.error('Failed to fetch plugin details:', response.status, response.statusText);
                        }
                    })
            } else {
                console.log("Token is not updated");
            }
        })

            .catch(error => {
                console.error('Error during the process:', error);
            });
    }
    )
}
